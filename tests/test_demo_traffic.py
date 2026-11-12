"""Contract tests for the realistic-traffic demo (no stack required)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from scripts.demo_traffic import TURNS, Demo, main, parse_args, render, run, summarize

DEMO = Demo(base_url="http://gateway.test", keycloak_url="http://kc.test", timeout=5.0)
CONVERSATION = "conv-thread"


def _transport(
    seen: list[httpx.Request],
    *,
    status: int = 200,
    body: Any | None = None,
) -> httpx.MockTransport:
    """Fake Keycloak + gateway: tokens are named after the user who asked."""

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/token"):
            form = parse_qs(request.content.decode())
            return httpx.Response(200, json={"access_token": f"token-{form['username'][0]}"})
        if status != 200:
            if isinstance(body, dict):
                return httpx.Response(status, json=body)
            return httpx.Response(status, text=str(body))
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "conversation_id": payload.get("conversation_id", CONVERSATION),
                "message": {"role": "assistant", "content": "ok"},
                "model": "gpt-4o-mini",
                "route": "cloud-primary",
                "classification": "PUBLIC",
                "reason": "no_markers",
                "confidence": 0.9875,
                "restored_tokens": 0,
            },
        )

    return httpx.MockTransport(handle)


def _chats(seen: list[httpx.Request]) -> list[dict[str, Any]]:
    return [json.loads(request.content) for request in seen if request.url.path == "/v1/chat"]


def test_every_turn_authenticates_as_its_own_user() -> None:
    """The corpus spans three principals; a shared token would hide RBAC."""
    seen: list[httpx.Request] = []
    assert run(DEMO, transport=_transport(seen)) == 0

    chats = [request for request in seen if request.url.path == "/v1/chat"]
    assert len(chats) == len(TURNS)
    assert [request.headers["authorization"] for request in chats] == [
        f"Bearer token-{turn.user}" for turn in TURNS
    ]
    tokens = [request for request in seen if request.url.path.endswith("/token")]
    assert len(tokens) == len({turn.user for turn in TURNS})


def test_the_thread_reuses_one_conversation_id() -> None:
    """Vault markers and the canary are scoped to a thread, so it must be one."""
    seen: list[httpx.Request] = []
    assert run(DEMO, transport=_transport(seen)) == 0

    thread = [body for body in _chats(seen) if "conversation_id" in body]
    assert len(thread) == sum(1 for turn in TURNS if turn.thread) - 1
    assert {body["conversation_id"] for body in thread} == {CONVERSATION}
    assert all(len(body["messages"]) == 1 for body in _chats(seen))


def test_a_blocked_turn_is_evidence_not_a_failure(capsys: pytest.CaptureFixture[str]) -> None:
    seen: list[httpx.Request] = []
    assert (
        run(
            DEMO,
            as_json=True,
            transport=_transport(seen, status=403, body={"detail": "quarantined"}),
        )
        == 0
    )

    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {row["outcome"] for row in rows} == {"blocked"}
    assert rows[0]["status"] == 403


def test_an_injection_block_is_evidence_not_an_answer() -> None:
    """A 200 with blocked=true is a guardrail verdict, not a model answer."""
    row = summarize(
        "injection",
        200,
        {
            "blocked": True,
            "block_reason": "prompt_injection_detected",
            "message": {"role": "assistant", "content": "Request blocked: ..."},
            "route": "local-llama",
            "classification": "CONFIDENTIAL",
        },
    )
    assert row["outcome"] == "blocked"
    assert row["detail"] == "prompt_injection_detected"
    assert "content" not in row


def test_a_response_the_demo_cannot_read_is_a_failure(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A 500 with an HTML body is a broken stack, not a guardrail verdict."""
    seen: list[httpx.Request] = []
    assert (
        run(DEMO, as_json=True, transport=_transport(seen, status=500, body="<html>boom</html>"))
        == 1
    )

    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [row["outcome"] for row in rows] == ["unexpected"] * len(TURNS)


def test_json_mode_emits_one_object_per_turn(capsys: pytest.CaptureFixture[str]) -> None:
    seen: list[httpx.Request] = []
    assert run(DEMO, as_json=True, transport=_transport(seen)) == 0

    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [row["label"] for row in rows] == [turn.label for turn in TURNS]
    assert all(row["route"] == "cloud-primary" for row in rows)


def test_the_table_shows_the_routing_evidence(capsys: pytest.CaptureFixture[str]) -> None:
    seen: list[httpx.Request] = []
    assert run(DEMO, transport=_transport(seen)) == 0

    out = capsys.readouterr().out
    assert "cloud-primary" in out
    assert "PUBLIC" in out
    assert f"conv={CONVERSATION}" in out


def test_a_turn_summary_never_carries_model_text() -> None:
    """Traces and terminals are shared; the answer stays in the audit ledger."""
    row = summarize(
        "label",
        200,
        {
            "conversation_id": "conv",
            "message": {"role": "assistant", "content": "TOP-SECRET-COMPLETION"},
            "route": "local-llama",
            "classification": "CONFIDENTIAL",
            "confidence": 0.9,
            "restored_tokens": 2,
        },
    )
    assert row["chars"] == len("TOP-SECRET-COMPLETION")
    assert "TOP-SECRET-COMPLETION" not in json.dumps(row)
    assert render(row).count("TOP-SECRET-COMPLETION") == 0


def test_the_corpus_covers_the_demo_cases() -> None:
    """Each guardrail the demo claims to exercise has at least one turn."""
    labels = [turn.label for turn in TURNS]
    assert len(labels) == len(set(labels))
    assert {turn.user for turn in TURNS} <= {"alice", "bob", "carol", "breakglass"}
    assert sum(1 for turn in TURNS if turn.thread) >= 3

    content = "\n".join(turn.content for turn in TURNS).lower()
    assert "example.com" in content  # DLP redaction + restore
    assert "iban" in content
    assert "revenue forecast" in content  # confidential by content
    assert "indemnity" in content
    assert "ignore all previous instructions" in content  # extraction probe


def test_password_can_come_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BASTION_DEMO_PASSWORD", "from-env")
    assert parse_args([]).password == "from-env"


def test_main_is_wired_to_the_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    """``main`` must pass the parsed flags through, not the defaults."""
    calls: list[Demo] = []

    def fake_run(demo: Demo, *, as_json: bool = False, transport: Any = None) -> int:
        del as_json, transport
        calls.append(demo)
        return 0

    monkeypatch.setattr("scripts.demo_traffic.run", fake_run)
    assert main(["--base-url", "http://elsewhere:9000", "--timeout", "9"]) == 0
    assert calls[0].base_url == "http://elsewhere:9000"
    assert calls[0].timeout == 9.0
