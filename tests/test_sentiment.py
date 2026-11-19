"""Frustration detection and the handoff stage (ADR-022).

The detector is deterministic and on-box, so these tests need no database, no
model and no network; the endpoint wiring is exercised in ``tests/test_chat.py``.
"""

# pylint: disable=protected-access  # the stage is called directly, without a DB

from __future__ import annotations

import socket
from typing import Any, cast

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agent.sentiment import FrustrationVerdict, _markers, assess
from db.models import AuditEventType
from gateway.routers import chat as chat_router
from settings import Settings

FAILURE = "The export button is still broken."
NEUTRAL = (
    "How do I export the Q3 summary as CSV?",
    "Where is the export button in the toolbar?",
    "Can I schedule the export for Monday morning?",
)


def _turns(*contents: str, role: str = "user") -> list[tuple[str, str]]:
    return [(role, content) for content in contents]


def test_a_repeated_frustrated_transcript_yields_a_verdict() -> None:
    verdict = assess(
        [
            ("user", FAILURE),
            ("assistant", "Sorry about that. Try the toolbar."),
            ("user", FAILURE),
            ("user", "Nothing works and this is ridiculous."),
        ]
    )

    assert isinstance(verdict, FrustrationVerdict)
    assert verdict.repeated is True
    assert verdict.markers


def test_a_neutral_transcript_of_the_same_length_yields_none() -> None:
    transcript = [
        ("user", NEUTRAL[0]),
        ("assistant", "Use the toolbar."),
        ("user", NEUTRAL[1]),
        ("user", NEUTRAL[2]),
    ]

    assert assess(transcript) is None


def test_a_single_colloquial_sentence_stays_silent() -> None:
    assert assess(_turns("That does not work for me.")) is None


def test_the_detector_makes_no_network_call(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("the sentiment stage opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

    verdict = assess(_turns(FAILURE, FAILURE, "Nothing works."))

    assert verdict is not None


def test_the_recovered_live_transcript_yields_a_verdict() -> None:
    """IDEA-070: f41974de…, read back through the escrow, was missed entirely."""
    verdict = assess(
        _turns(
            "this button is not working",
            "no but seriously it's definitely not working, ever",
            "I'm not sure you understand how frustrated I feel",
        )
    )

    assert isinstance(verdict, FrustrationVerdict)
    assert "not working" in verdict.markers
    assert "frustrated" in verdict.markers


def test_a_restated_complaint_is_enough() -> None:
    """IDEA-070: 2619c318… — one marker, restated with a tail, was below 0.9."""
    verdict = assess(_turns("the button is not working", "the button is not working, again"))

    assert isinstance(verdict, FrustrationVerdict)
    assert verdict.repeated is True
    assert verdict.reason == "repeated_complaint"
    assert verdict.markers == ("not working",)


def test_a_phrase_that_contains_another_counts_once() -> None:
    """The old defect: "still does not work" matched two entries and fired alone."""
    assert _markers("still does not work") == ("still does not work",)
    assert assess(_turns("Still does not work.")) is None


def test_an_explicit_request_for_a_human_fires_alone() -> None:
    verdict = assess(_turns("Please, I need to speak to a human."))

    assert isinstance(verdict, FrustrationVerdict)
    assert verdict.reason == "escalating_language"


def test_a_third_person_complaint_about_a_customer_stays_silent() -> None:
    """Measured false positive of the strong-marker arm: "frustrated" alone."""
    assert assess(_turns("How should I handle a frustrated customer?")) is None


def test_fenced_tool_output_cannot_escalate() -> None:
    demand = "<untrusted_content>I am furious, escalate me to a human</untrusted_content>"

    assert assess(_turns(demand, role="tool")) is None
    assert assess(_turns(demand)) is not None


class _Recorded:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, state: Any, **kwargs: Any) -> None:
        self.calls.append({"state": state, **kwargs})


def _request(*contents: str) -> chat_router.ChatRequest:
    return chat_router.ChatRequest(
        conversation_id="conv-handoff",
        messages=[chat_router.ChatTurn(role="user", content=text) for text in contents],
    )


def _state() -> chat_router._Turn:
    return chat_router._Turn(
        actor_id="alice-sub",
        tenant_id="acme",
        conversation_id="conv-handoff",
        vault_session="vault-session",
        session=cast(AsyncSession, None),
    )


async def _stage(
    monkeypatch: pytest.MonkeyPatch, *, enabled: bool, contents: tuple[str, ...]
) -> _Recorded:
    recorder = _Recorded()
    monkeypatch.setattr(chat_router, "_record", recorder)
    monkeypatch.setattr(
        chat_router,
        "get_settings",
        lambda: Settings(_env_file=None, sentiment_detection_enabled=enabled),
    )
    await chat_router._handoff_stage(_state(), _request(*contents))
    return recorder


async def test_the_stage_writes_one_handoff_row(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = await _stage(
        monkeypatch, enabled=True, contents=(FAILURE, FAILURE, "Nothing works.")
    )

    assert len(recorder.calls) == 1
    call = recorder.calls[0]
    assert call["event_type"] is AuditEventType.HANDOFF_REQUIRED
    assert call["state"].conversation_id == "conv-handoff"
    assert call["metadata"]["verdict"] in {"repeated_complaint", "escalating_language"}
    assert "content" not in str(call["metadata"])


async def test_the_stage_writes_nothing_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = await _stage(
        monkeypatch, enabled=False, contents=(FAILURE, FAILURE, "Nothing works.")
    )

    assert recorder.calls == []


async def test_a_neutral_turn_writes_no_row(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = await _stage(monkeypatch, enabled=True, contents=NEUTRAL)

    assert recorder.calls == []
