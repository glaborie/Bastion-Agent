"""Dashboard, approval API and audit API integration tests (ADR-003/ADR-007).

These tests need a disposable PostgreSQL instance; see ``tests/conftest.py``.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from db.audit import append_audit_event
from db.models import (
    ApprovalStatus,
    AuditEventType,
    AuditLog,
    PendingApproval,
    fingerprint_request,
    hash_approval_token,
    sign_approval_token,
    utcnow,
)
from db.session import get_db_session
from gateway.auth.oidc import Principal
from gateway.auth.rbac import AuthContext, get_auth_context
from gateway.auth.session import SessionRecord
from gateway.main import create_app
from tests.conftest import requires_database

pytestmark = [pytest.mark.integration, requires_database]

ALICE = Principal(subject="alice-sub", username="alice", roles=frozenset({"operator"}))
BOB = Principal(subject="bob-sub", username="bob", roles=frozenset({"operator", "analyst"}))
CAROL = Principal(subject="carol-sub", username="carol", roles=frozenset({"analyst"}))
DAVE = Principal(subject="dave-sub", username="dave", roles=frozenset({"readonly"}))

ARGUMENTS: dict[str, Any] = {"path": "/srv/reports/q3.csv", "content": "revenue"}
SECRET = "integration-test-hmac-secret"


def build_ticket(
    *,
    initiator_id: str = ALICE.subject,
    ttl_seconds: int = 900,
    ticket_id: uuid.UUID | None = None,
) -> PendingApproval:
    now = utcnow()
    expires_at = PendingApproval.expiry_for(now, ttl_seconds)
    identifier = ticket_id or uuid.uuid4()
    fingerprint = fingerprint_request("execute_file_write", ARGUMENTS)
    token = sign_approval_token(
        ticket_id=identifier,
        request_fingerprint=fingerprint,
        expires_at=expires_at,
        secret=SECRET,
    )
    return PendingApproval(
        ticket_id=identifier,
        session_id="session-four-eyes",
        initiator_id=initiator_id,
        tool_name="execute_file_write",
        tool_arguments=ARGUMENTS,
        required_role="operator",
        request_fingerprint=fingerprint,
        approval_token_hash=hash_approval_token(token),
        token_expires_at=expires_at,
        created_at=now,
    )


async def seed_ticket(engine: AsyncEngine, ticket: PendingApproval) -> uuid.UUID:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        session.add(ticket)
        await session.commit()
    return ticket.ticket_id


def session_context(principal: Principal, *, csrf_token: str = "csrf-token") -> AuthContext:
    now = utcnow()
    record = SessionRecord(
        session_id="session-1",
        principal=principal,
        access_token="access-token",
        csrf_token=csrf_token,
        created_at=now,
        access_expires_at=now + timedelta(minutes=5),
        last_seen_at=now,
    )
    return AuthContext(principal=principal, method="session", session=record)


@pytest_asyncio.fixture
async def api(
    db_engine: AsyncEngine,
) -> AsyncIterator[tuple[httpx.AsyncClient, dict[str, AuthContext]]]:
    app = create_app()
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def override_db() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
            except BaseException:
                await session.rollback()
                raise
            else:
                await session.commit()

    state = {"context": AuthContext(principal=BOB, method="bearer")}
    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_auth_context] = lambda: state["context"]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        follow_redirects=False,
    ) as client:
        yield client, state


async def test_dashboard_renders_the_approval_queue(api: tuple[httpx.AsyncClient, Any]) -> None:
    client, _state = api
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert "Command Control" in response.text
    assert "No tickets are waiting for approval." in response.text
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


async def test_json_approvals_respect_four_eyes(
    api: tuple[httpx.AsyncClient, Any], db_engine: AsyncEngine
) -> None:
    client, state = api
    ticket_id = await seed_ticket(db_engine, build_ticket())

    state["context"] = AuthContext(principal=BOB, method="bearer")
    response = await client.get("/api/approvals")
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["approvals"][0]["ticket_id"] == str(ticket_id)
    assert payload["approvals"][0]["decidable"] is True

    state["context"] = AuthContext(principal=ALICE, method="bearer")
    as_initiator = (await client.get("/api/approvals")).json()
    assert as_initiator["approvals"][0]["decidable"] is False


async def test_initiator_cannot_approve_their_own_ticket(
    api: tuple[httpx.AsyncClient, Any], db_engine: AsyncEngine
) -> None:
    client, state = api
    ticket_id = await seed_ticket(db_engine, build_ticket())
    state["context"] = AuthContext(principal=ALICE, method="bearer")

    response = await client.post(f"/api/approvals/{ticket_id}/action", data={"action": "approve"})
    assert response.status_code == 403
    assert "four-eyes" in response.json()["detail"]

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        ticket = await session.get(PendingApproval, ticket_id)
        assert ticket is not None
        assert ticket.status == ApprovalStatus.PENDING
        assert ticket.approver_id is None


async def test_second_operator_approval_is_audited(
    api: tuple[httpx.AsyncClient, Any], db_engine: AsyncEngine
) -> None:
    client, state = api
    ticket_id = await seed_ticket(db_engine, build_ticket())
    state["context"] = AuthContext(principal=BOB, method="bearer")

    response = await client.post(
        f"/api/approvals/{ticket_id}/action",
        data={"action": "approve", "reason": "reviewed the diff"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        ticket = await session.get(PendingApproval, ticket_id)
        assert ticket is not None
        assert ticket.status == ApprovalStatus.APPROVED
        assert ticket.approver_id == BOB.subject
        assert ticket.decided_at is not None
        assert ticket.decision_reason == "reviewed the diff"

        events = list(
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.event_type == AuditEventType.APPROVAL_GRANTED)
                )
            ).scalars()
        )
        assert len(events) == 1
        assert events[0].actor_id == BOB.subject
        # The free-text reason is hashed in the ledger, never stored there.
        assert "reason_sha256" in events[0].metadata_json
        assert "reviewed the diff" not in json.dumps(events[0].metadata_json)

    verification = await client.post("/api/audit/verify")
    assert verification.status_code == 200
    assert verification.json()["ok"] is True
    assert verification.json()["checked"] == 1


async def test_expired_ticket_cannot_be_decided(
    api: tuple[httpx.AsyncClient, Any], db_engine: AsyncEngine
) -> None:
    client, state = api
    ticket_id = await seed_ticket(db_engine, build_ticket(ttl_seconds=1))
    state["context"] = AuthContext(principal=BOB, method="bearer")
    # Force expiry without waiting for the TTL.
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        ticket = await session.get(PendingApproval, ticket_id)
        assert ticket is not None
        ticket.token_expires_at = utcnow() - timedelta(seconds=1)
        await session.commit()

    response = await client.post(f"/api/approvals/{ticket_id}/action", data={"action": "approve"})
    assert response.status_code == 409
    assert "window has closed" in response.json()["detail"]


@pytest.mark.parametrize("principal", [CAROL, DAVE])
async def test_roles_without_operator_access_are_forbidden(
    api: tuple[httpx.AsyncClient, Any], principal: Principal
) -> None:
    client, state = api
    state["context"] = AuthContext(principal=principal, method="bearer")
    assert (await client.get("/api/approvals")).status_code == 403


async def test_session_auth_requires_csrf(
    api: tuple[httpx.AsyncClient, Any], db_engine: AsyncEngine
) -> None:
    client, state = api
    ticket_id = await seed_ticket(db_engine, build_ticket())
    state["context"] = session_context(BOB)

    assert (
        await client.post(f"/api/approvals/{ticket_id}/action", data={"action": "approve"})
    ).status_code == 403

    response = await client.post(
        f"/api/approvals/{ticket_id}/action",
        data={"action": "approve"},
        headers={"X-CSRF-Token": "csrf-token"},
    )
    assert response.status_code == 200


async def test_audit_filters_and_pagination(
    api: tuple[httpx.AsyncClient, Any], db_engine: AsyncEngine
) -> None:
    client, _state = api
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        for index in range(3):
            await append_audit_event(
                session,
                actor_id="alice-sub",
                event_type=AuditEventType.INPUT_RECEIVED,
                session_id="session-audit",
                payload={"n": index},
            )
        await append_audit_event(
            session,
            actor_id="bob-sub",
            event_type=AuditEventType.EGRESS_FILTERED,
            session_id="session-audit",
            payload={"clean": True},
        )
        await session.commit()

    filtered = await client.get("/api/audit", params={"event_type": "INPUT_RECEIVED"})
    assert filtered.status_code == 200
    assert len(filtered.json()["records"]) == 3

    first_page = await client.get("/api/audit", params={"limit": 2})
    payload = first_page.json()
    assert len(payload["records"]) == 2
    assert payload["has_more"] is True
    next_before_id = payload["next_before_id"]
    assert next_before_id is not None

    second_page = await client.get("/api/audit", params={"limit": 2, "before_id": next_before_id})
    assert len(second_page.json()["records"]) == 2
    assert second_page.json()["next_before_id"] is None

    by_actor = await client.get("/api/audit", params={"actor_id": "bob"})
    assert len(by_actor.json()["records"]) == 1

    by_session = await client.get("/api/audit", params={"session_id": "session-audit"})
    assert len(by_session.json()["records"]) == 4


async def test_audit_rejects_unknown_event_type(api: tuple[httpx.AsyncClient, Any]) -> None:
    client, _state = api
    response = await client.get("/api/audit", params={"event_type": "NOT_REAL"})
    assert response.status_code == 422


async def test_audit_page_and_session_inspector(
    api: tuple[httpx.AsyncClient, Any], db_engine: AsyncEngine
) -> None:
    client, _state = api
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        await append_audit_event(
            session,
            actor_id="bob-sub",
            event_type=AuditEventType.INPUT_RECEIVED,
            session_id="session-inspector",
            payload={"n": 1},
        )
        await session.commit()

    audit_page = await client.get("/dashboard/audit")
    assert audit_page.status_code == 200
    assert "Audit ledger" in audit_page.text

    session_page = await client.get("/dashboard/sessions/session-inspector")
    assert session_page.status_code == 200
    assert "session-inspector" in session_page.text
    assert "INPUT_RECEIVED" in session_page.text


async def test_eval_card_reports_a_missing_run(
    api: tuple[httpx.AsyncClient, Any], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from settings import reset_settings_cache

    monkeypatch.setenv("EVAL_REPORT_PATH", str(tmp_path / "missing.json"))
    reset_settings_cache()
    try:
        client, _state = api
        response = await client.get("/api/evals/latest")
        assert response.status_code == 200
        assert response.json()["available"] is False
    finally:
        reset_settings_cache()


async def test_unauthenticated_dashboard_redirects_to_login() -> None:
    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=False
    ) as client:
        response = await client.get("/dashboard")
        assert response.status_code == 303
        assert response.headers["location"] == "/auth/login?next=%2Fdashboard"

        htmx = await client.get("/api/approvals", headers={"HX-Request": "true"})
        assert htmx.status_code == 401
        assert htmx.headers["hx-redirect"].startswith("/auth/login?next=")
