"""Demo console: registry, RBAC and scenario evidence (ADR-007).

The page must never be a command surface: a run request carries a scenario id,
resolved against a fixed server-side registry, and the run executes on the
worker. The canary scenario is exercised against the real sanitizer and vault
(fakeredis), so the acceptance evidence — ``canary_leak`` with empty delivered
text — is produced by the gate rather than asserted from a narrative.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
import pytest_asyncio
from fakeredis import FakeAsyncRedis
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from agent.demo.runs import STATUS_QUEUED, load_run
from agent.demo.scenarios import (
    SCENARIOS,
    ScenarioContext,
    get_scenario,
    run_egress_demo,
)
from agent.dlp.vault import TokenVault
from db.models import ApprovalStatus, PendingApproval
from gateway.approvals import ApprovalDecisionError, decide_ticket
from gateway.auth.oidc import Principal
from gateway.auth.rbac import AuthContext, get_auth_context
from gateway.dashboard.demo import get_demo_redis
from gateway.main import create_app
from settings import reset_settings_cache
from tests.conftest import requires_database

BOB = Principal(subject="bob-sub", tenant_id="acme", username="bob", roles=frozenset({"operator"}))
CAROL = Principal(
    subject="carol-sub", tenant_id="acme", username="carol", roles=frozenset({"analyst"})
)
DAVE = Principal(
    subject="dave-sub", tenant_id="acme", username="dave", roles=frozenset({"readonly"})
)

LISTED_SCRIPTS = (
    "scripts/demo_classifier.py",
    "scripts/demo_egress.py",
    "scripts/demo_model_canary.py",
    "scripts/demo_tool_request.py",
    "scripts/demo_traffic.py",
    "scripts/seed_demo_approval.py",
)

VAULT_KEY = b"d" * 32


@pytest_asyncio.fixture
async def api(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[tuple[httpx.AsyncClient, dict[str, AuthContext], Any, list[dict[str, Any]]]]:
    """The real app, a bearer context, a fake run store and a recorded queue."""
    app = create_app()
    state = {"context": AuthContext(principal=BOB, method="bearer")}
    store = FakeAsyncRedis(decode_responses=True)
    calls: list[dict[str, Any]] = []

    async def fake_enqueue(**kwargs: Any) -> bool:
        calls.append(kwargs)
        return True

    app.dependency_overrides[get_auth_context] = lambda: state["context"]
    app.dependency_overrides[get_demo_redis] = lambda: cast(Redis, store)
    monkeypatch.setattr("gateway.dashboard.demo.enqueue_demo_run", fake_enqueue)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        follow_redirects=False,
    ) as client:
        yield client, state, store, calls
    await store.aclose()


async def test_the_page_lists_every_script_with_its_control_and_evidence(
    api: tuple[httpx.AsyncClient, dict[str, AuthContext], Any, list[dict[str, Any]]],
) -> None:
    client, _state, _store, _calls = api
    response = await client.get("/dashboard/demo")

    assert response.status_code == 200
    for script in LISTED_SCRIPTS:
        assert script in response.text, script
    assert response.text.count("Run scenario") == sum(1 for item in SCENARIOS if item.runnable)
    assert "CLI only" in response.text
    for scenario in SCENARIOS:
        assert scenario.control in response.text
        assert scenario.evidence in response.text
        assert all(need in response.text for need in scenario.needs[:1])
    assert "GPU:" in response.text
    assert "live model" in response.text
    assert "worker" in response.text


@pytest.mark.parametrize("principal", [CAROL, DAVE])
async def test_non_operators_cannot_see_or_start_a_scenario(
    api: tuple[httpx.AsyncClient, dict[str, AuthContext], Any, list[dict[str, Any]]],
    principal: Principal,
) -> None:
    client, state, _store, calls = api
    state["context"] = AuthContext(principal=principal, method="bearer")

    assert (await client.get("/dashboard/demo")).status_code == 403
    started = await client.post("/dashboard/demo/runs", data={"scenario_id": "demo_classifier"})
    assert started.status_code == 403
    polled = await client.get(f"/api/dashboard/demo/runs/{uuid.uuid4().hex}")
    assert polled.status_code == 403
    assert calls == []


async def test_an_unknown_scenario_executes_nothing(
    api: tuple[httpx.AsyncClient, dict[str, AuthContext], Any, list[dict[str, Any]]],
) -> None:
    client, _state, store, calls = api
    response = await client.post("/dashboard/demo/runs", data={"scenario_id": "rm-rf"})

    assert response.status_code == 404
    assert calls == []
    assert await store.keys("demo:run:*") == []


async def test_a_cli_only_scenario_is_rejected(
    api: tuple[httpx.AsyncClient, dict[str, AuthContext], Any, list[dict[str, Any]]],
) -> None:
    client, _state, _store, calls = api
    response = await client.post("/dashboard/demo/runs", data={"scenario_id": "demo_traffic"})

    assert response.status_code == 422
    assert calls == []


async def test_request_fields_cannot_supply_a_command_or_an_actor(
    api: tuple[httpx.AsyncClient, dict[str, AuthContext], Any, list[dict[str, Any]]],
) -> None:
    """Only the registry id survives; the actor is the signed-in principal."""
    client, _state, store, calls = api
    response = await client.post(
        "/dashboard/demo/runs",
        data={
            "scenario_id": "demo_classifier",
            "command": "rm -rf /",
            "script": "/etc/passwd",
            "argv": "--actor-sub alice-sub",
            "actor_id": "alice-sub",
        },
    )

    assert response.status_code == 200
    assert len(calls) == 1
    assert set(calls[0]) == {
        "run_id",
        "scenario_id",
        "actor_id",
        "tenant_id",
        "roles",
        "session_id",
    }
    assert calls[0]["scenario_id"] == "demo_classifier"
    assert calls[0]["actor_id"] == BOB.subject
    assert calls[0]["roles"] == ["operator"]

    run = await load_run(store, calls[0]["run_id"])
    assert run is not None
    assert run.status == STATUS_QUEUED
    assert run.actor_id == BOB.subject
    assert run.scenario_id == "demo_classifier"


async def test_the_egress_scenario_blocks_the_leak_with_empty_delivered_text() -> None:
    redis = FakeAsyncRedis(decode_responses=True)
    vault = TokenVault(cast(Redis, redis), key=VAULT_KEY, ttl_seconds=60)
    try:
        outcome = await run_egress_demo(
            cast(Redis, redis),
            vault,
            tenant_id="acme",
            session_id=f"dashboard-demo-test-{uuid.uuid4()}",
        )
    finally:
        await redis.aclose()

    facts = dict(outcome.facts)
    assert facts["reason"] == "canary_leak"
    assert facts["delivered_chars"] == "0"
    assert facts["delivered_text"] == '""'
    assert facts["quarantined"] == "yes"
    assert facts["restored_tokens"] == "1"
    assert facts["fence_tags"] == "1"
    assert "BASTION-CANARY-" not in repr(outcome)


async def test_the_run_panel_polls_once_and_stops_when_terminal(
    api: tuple[httpx.AsyncClient, dict[str, AuthContext], Any, list[dict[str, Any]]],
) -> None:
    client, _state, store, calls = api
    started = await client.post("/dashboard/demo/runs", data={"scenario_id": "demo_classifier"})
    assert started.status_code == 200
    run_id = calls[0]["run_id"]
    assert f"/api/dashboard/demo/runs/{run_id}" in started.text

    run = await load_run(store, run_id)
    assert run is not None
    await store.set(
        f"demo:run:{run_id}",
        replace(run, status="succeeded", summary="done").to_json(),
    )
    polled = await client.get(f"/api/dashboard/demo/runs/{run_id}")
    assert polled.status_code == 200
    assert "succeeded" in polled.text
    assert "hx-trigger" not in polled.text


@pytest.mark.integration
@requires_database
async def test_the_tool_scenario_uses_the_signed_in_principal_and_keeps_four_eyes(
    db_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """No request field becomes the initiator; a second principal still decides."""
    from db import session as db_session

    monkeypatch.setattr(db_session, "_engine", db_engine)
    monkeypatch.setattr(db_session, "_session_factory", None)
    monkeypatch.setenv("TOOL_WORKSPACE_ROOT", str(tmp_path / "workspace"))
    reset_settings_cache()
    try:
        handler = get_scenario("demo_tool_request").handler
        assert handler is not None
        outcome = await handler(
            ScenarioContext(
                run_id=uuid.uuid4().hex,
                actor_id="alice-sub",
                tenant_id="acme",
                actor_roles=frozenset({"operator"}),
                session_id="demo-four-eyes",
            )
        )

        facts = dict(outcome.facts)
        assert facts["initiator"] == "alice-sub"
        assert facts["status"] == "approval_pending"
        assert outcome.links == (
            ("Open the session timeline", "/dashboard/sessions/demo-four-eyes"),
        )
        ticket_id = uuid.UUID(facts["ticket_id"])

        factory = async_sessionmaker(db_engine, expire_on_commit=False)
        async with factory() as session:
            ticket = await session.get(PendingApproval, ticket_id)
            assert ticket is not None
            assert ticket.initiator_id == "alice-sub"
            assert ticket.status is ApprovalStatus.PENDING

            with pytest.raises(ApprovalDecisionError):
                await decide_ticket(
                    session,
                    ticket_id=ticket_id,
                    actor_id="alice-sub",
                    tenant_id="acme",
                    actor_roles=frozenset({"operator"}),
                    action="approve",
                )

            decided = await decide_ticket(
                session,
                ticket_id=ticket_id,
                actor_id="bob-sub",
                tenant_id="acme",
                actor_roles=frozenset({"operator"}),
                action="approve",
            )
            assert decided.status is ApprovalStatus.APPROVED
            assert decided.approver_id == "bob-sub"
    finally:
        reset_settings_cache()
