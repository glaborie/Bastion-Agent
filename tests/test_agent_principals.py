"""Non-human principals: registry ingress, session refusal and allowlists (ADR-027).

Pure tests run everywhere; the registry and ledger cases need PostgreSQL and are
marked ``integration`` (see ``tests/conftest.py``).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agent.tools.catalog import CatalogTool, get_tool_catalog, override_tool_catalog
from agent.tools.decorator import AgentContext, tool, unregister_tool
from agent.tools.errors import ToolNotAllowedError, ToolNotInCatalogError
from agent.tools.execution import request_tool_execution
from db.audit import append_audit_event, verify_audit_chain
from db.models import (
    GENESIS_HASH,
    AgentRegistry,
    AgentStatus,
    AuditEventType,
    AuditLog,
)
from gateway.auth.agents import authorize_agent, effective_tools
from gateway.auth.oidc import Principal, TokenValidationError
from scripts.validate_rbac import check as check_rbac
from scripts.validate_rbac import load_realm
from tests.conftest import disable_audit_guard, enable_audit_guard, requires_database

AGENT = Principal(
    subject="service-account-id",
    tenant_id="acme",
    roles=frozenset({"analyst"}),
    actor_type="agent",
    agent_id="bastion-agent-analyst",
)
HUMAN = Principal(subject="alice-sub", tenant_id="acme", roles=frozenset({"operator"}))


class _Validator:
    """A validator stub: the tests care about the decision, not RS256."""

    def __init__(self, principal: Principal | None) -> None:
        self._principal = principal

    async def validate_access_token(self, token: str) -> Principal:
        if self._principal is None:
            raise TokenValidationError("invalid_signature", "nope")
        return self._principal


def _login_app(principal: Principal | None, stored: list[str], requests_log: list[str]) -> Any:
    """The real login route, with only the IdP boundary stubbed."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from gateway.auth.rbac import get_session_manager, get_token_client, get_token_validator
    from gateway.routers import auth as auth_router

    class _Sessions:
        async def store_login_state(self, state: str, *_args: Any) -> None:
            stored.append(state)

    class _TokenClient:
        def authorization_url(self, **_kwargs: Any) -> str:
            requests_log.append("authorization_url")
            return "http://idp.test/auth"

    app = FastAPI()
    app.include_router(auth_router.router)
    app.dependency_overrides[get_token_client] = _TokenClient
    app.dependency_overrides[get_session_manager] = _Sessions
    app.dependency_overrides[get_token_validator] = lambda: _Validator(principal)
    return TestClient(app)


def test_refuse_agent_principal_allows_humans_and_anonymous() -> None:
    stored: list[str] = []
    calls: list[str] = []
    human = _login_app(HUMAN, stored, calls).get(
        "/auth/login", headers={"Authorization": "Bearer human-token"}, follow_redirects=False
    )
    anonymous = _login_app(None, stored, calls).get(
        "/auth/login", headers={"Authorization": "Bearer junk"}, follow_redirects=False
    )
    # Both reach the real login flow (a redirect to the IdP), so the guard only
    # refuses the agent case below.
    assert human.status_code == 303
    assert anonymous.status_code == 303
    assert len(stored) == 2


def test_agent_token_cannot_start_a_login_session() -> None:
    stored: list[str] = []
    calls: list[str] = []
    response = _login_app(AGENT, stored, calls).get(
        "/auth/login", headers={"Authorization": "Bearer agent-token"}, follow_redirects=False
    )
    assert response.status_code == 403
    # No `auth:session`/login-state key could be written: the refusal happens
    # before the route body, so neither the store nor the IdP was touched.
    assert not stored
    assert not calls

    callback = _login_app(AGENT, stored, calls).get(
        "/auth/callback?code=abc&state=xyz",
        headers={"Authorization": "Bearer agent-token"},
        follow_redirects=False,
    )
    assert callback.status_code == 403
    assert not stored
    assert not calls


def test_check_rbac_rejects_agent_client_without_registry_row() -> None:
    realm = load_realm(__import__("pathlib").Path("config/keycloak/realm-export.json"))
    errors, _, _ = check_rbac(realm, [], [])
    assert any("has no registry row" in error for error in errors)


def test_check_rbac_rejects_unknown_catalog_entry_and_unsatisfied_role() -> None:
    realm = load_realm(__import__("pathlib").Path("config/keycloak/realm-export.json"))
    registry = [
        {
            "agent_id": "bastion-agent-analyst",
            "owner_sub": "0a100000-0000-4000-8000-00000000a11c",
            "tenant_id": "acme",
            "status": "active",
            # ``read_file`` exists and is satisfied; the other two are the failures.
            "allowed_tools": ["read_file", "not_a_tool", "execute_file_write"],
            "allowed_route_aliases": ["local-llama"],
            "budget_key": "agent:bastion-agent-analyst",
        }
    ]
    from agent.tools import list_tools

    errors, _, _ = check_rbac(realm, list(list_tools()), registry)
    assert any("not in the catalog" in error for error in errors)
    assert any("do not satisfy" in error for error in errors)


def test_check_rbac_passes_on_the_seeded_realm() -> None:
    from agent.tools import list_tools

    realm = load_realm(__import__("pathlib").Path("config/keycloak/realm-export.json"))
    from db.agents import load_registry_seed

    errors, _, summary = check_rbac(realm, list(list_tools()), load_registry_seed())
    assert not errors
    assert summary["agents"] == 1


def test_agent_owner_cannot_decide_the_agents_ticket() -> None:
    from db.models import PendingApproval, utcnow

    ticket = PendingApproval(
        session_id="sess-agent",
        tenant_id="acme",
        initiator_id="service-account-id",
        initiator_owner_sub="alice-sub",
        tool_name="execute_file_write",
        required_role="operator",
        request_fingerprint="a" * 64,
        approval_token_hash="b" * 64,
        token_expires_at=utcnow() + timedelta(minutes=5),
    )
    assert ticket.can_be_decided_by("bob-sub")
    assert not ticket.can_be_decided_by("alice-sub")
    assert not ticket.can_be_decided_by("service-account-id")


def test_exported_v3_row_round_trips_and_recomputes() -> None:
    from db.export import ExportRecord
    from db.models import compute_record_hash, hash_payload

    moment = datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)
    metadata_hash = hash_payload({})
    payload_hash = hash_payload({"tool": "read_file"})
    record_hash = compute_record_hash(
        record_id=1,
        timestamp=moment,
        actor_id="service-account-id",
        event_type=str(AuditEventType.TOOL_EXECUTED),
        payload_hash=payload_hash,
        previous_hash=GENESIS_HASH,
        hash_version=3,
        metadata_hash=metadata_hash,
        actor_type="agent",
        agent_id="bastion-agent-analyst",
        owner_sub="alice-sub",
    )
    record = ExportRecord(
        id=1,
        timestamp=moment,
        tenant_id="acme",
        actor_id="service-account-id",
        event_type=str(AuditEventType.TOOL_EXECUTED),
        payload_hash=payload_hash,
        previous_hash=GENESIS_HASH,
        record_hash=record_hash,
        hash_version=3,
        metadata_hash=metadata_hash,
        actor_type="agent",
        agent_id="bastion-agent-analyst",
        owner_sub="alice-sub",
    )
    assert ExportRecord.from_dict(record.to_dict()) == record


@pytest.mark.asyncio
@requires_database
async def test_agent_token_is_admitted_on_the_api_but_never_on_a_session_route(
    session: AsyncSession,
) -> None:
    from typing import cast

    from starlette.requests import Request

    from gateway.auth.rbac import get_auth_context

    session.add(
        AgentRegistry(
            agent_id="bastion-agent-analyst",
            owner_sub="alice-sub",
            tenant_id="acme",
            allowed_tools=["read_file"],
            allowed_route_aliases=["local-llama"],
            budget_key="agent:bastion-agent-analyst",
        )
    )
    await session.flush()

    def request(path: str) -> Request:
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": path,
                "query_string": b"",
                "scheme": "http",
                "server": ("testserver", 80),
                "headers": [(b"authorization", b"Bearer agent-token")],
            }
        )

    context = await get_auth_context(
        request("/v1/chat"),
        validator=cast(Any, _Validator(AGENT)),
        sessions=cast(Any, None),
        session=session,
    )
    assert context.actor_type == "agent"
    assert context.owner_sub == "alice-sub"
    assert context.allowed_tools == frozenset({"read_file"})
    assert context.rate_limit_subject == "agent:bastion-agent-analyst"

    with pytest.raises(HTTPException) as refusal:
        await get_auth_context(
            request("/dashboard"),
            validator=cast(Any, _Validator(AGENT)),
            sessions=cast(Any, None),
            session=session,
        )
    assert refusal.value.status_code == 403


@pytest.mark.asyncio
@requires_database
async def test_suspended_registry_row_is_refused_at_ingress_and_recorded(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway import queue as queue_module

    enqueued: list[tuple[str, str]] = []
    monkeypatch.setattr(
        queue_module,
        "enqueue_tool_resume",
        lambda tenant_id, ticket_id: enqueued.append((tenant_id, ticket_id)),
    )
    session.add(
        AgentRegistry(
            agent_id="bastion-agent-analyst",
            owner_sub="alice-sub",
            tenant_id="acme",
            status=AgentStatus.SUSPENDED,
            allowed_tools=["read_file"],
            allowed_route_aliases=["local-llama"],
        )
    )
    await session.flush()

    with pytest.raises(HTTPException) as refusal:
        await authorize_agent(session, AGENT, "/v1/chat")
    assert refusal.value.status_code == 403

    # The denial lives in its own committed transaction, so a request rollback
    # cannot erase the evidence (checked through a second session below).
    await session.rollback()
    refreshed = await session.execute(select(AuditLog).where(AuditLog.actor_type == "agent"))
    rows = refreshed.scalars().all()
    assert rows and rows[-1].event_type == AuditEventType.SECURITY_INCIDENT
    assert rows[-1].agent_id == "bastion-agent-analyst"
    assert rows[-1].owner_sub == "alice-sub"
    # The refusal happened at ingress, so the enqueue bridge was never reached.
    assert not enqueued


@pytest.mark.asyncio
@requires_database
async def test_registered_agent_is_admitted_only_on_the_api(session: AsyncSession) -> None:
    session.add(
        AgentRegistry(
            agent_id="bastion-agent-analyst",
            owner_sub="alice-sub",
            tenant_id="acme",
            allowed_tools=["read_file", "execute_payments"],
            allowed_route_aliases=["local-llama"],
        )
    )
    await session.flush()
    entry = await authorize_agent(session, AGENT, "/v1/chat")
    assert entry.agent_id == "bastion-agent-analyst"
    # The allowlist is intersected with the catalog, never trusted alone.
    assert effective_tools(entry) == frozenset({"read_file"})

    with pytest.raises(HTTPException) as refusal:
        await authorize_agent(session, AGENT, "/dashboard")
    assert refusal.value.status_code == 403


@pytest.mark.asyncio
@requires_database
async def test_tool_allowlist_refuses_an_approved_tool(session: AsyncSession) -> None:
    @tool(
        name="test_allowed_read",
        description="Test-only read tool.",
        read_only=True,
        required_role="analyst",
    )
    async def allowed_read(path: str, context: AgentContext) -> dict[str, str]:
        return {"path": path}

    @tool(
        name="test_unapproved_read",
        description="Test-only tool the catalog never approved.",
        read_only=True,
        required_role="analyst",
    )
    async def unapproved_read(path: str, context: AgentContext) -> dict[str, str]:
        return {"path": path}

    entry = CatalogTool(
        name="test_allowed_read",
        description="Test-only read tool.",
        read_only=True,
        required_role="analyst",
        require_approval=False,
        arguments={"path": {"type": "string", "required": True}},
    )
    try:
        with override_tool_catalog(extra={entry.name: entry}):
            assert get_tool_catalog().names() >= {"test_allowed_read"}
            context = AgentContext(
                actor_id="service-account-id",
                tenant_id="acme",
                roles=frozenset({"analyst"}),
                session_id="sess-agent",
                actor_type="agent",
                agent_id="bastion-agent-analyst",
                owner_sub="alice-sub",
                allowed_tools=frozenset({"read_file"}),
            )
            with pytest.raises(ToolNotAllowedError):
                await request_tool_execution(
                    session,
                    tool_name="test_allowed_read",
                    arguments={"path": "a.txt"},
                    context=context,
                )
            # A tool absent from the catalog is refused even when allowlisted.
            context = AgentContext(
                actor_id="service-account-id",
                tenant_id="acme",
                roles=frozenset({"analyst"}),
                session_id="sess-agent",
                allowed_tools=frozenset({"test_unapproved_read"}),
            )
            with pytest.raises(ToolNotInCatalogError):
                await request_tool_execution(
                    session,
                    tool_name="test_unapproved_read",
                    arguments={"path": "a.txt"},
                    context=context,
                )
    finally:
        unregister_tool("test_allowed_read")
        unregister_tool("test_unapproved_read")


@pytest.mark.asyncio
@requires_database
async def test_v3_ledger_links_old_rows_and_breaks_on_actor_edit(
    session: AsyncSession,
) -> None:
    """v1/v2 rows keep their preimage; a v3 agent row is tamper-evident."""
    from db.models import AUDIT_LOG_ID_SEQUENCE, compute_record_hash, hash_payload

    moment = datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)
    previous = GENESIS_HASH
    for version in (1, 2):
        # Allocate like the append path does: another test in the same database
        # may have left rows behind, so a fixed id would collide.
        record_id = int(
            (await session.execute(select(AUDIT_LOG_ID_SEQUENCE.next_value()))).scalar_one()
        )
        metadata_hash = hash_payload({}) if version == 2 else None
        row = AuditLog(
            id=record_id,
            timestamp=moment,
            tenant_id="acme",
            actor_id="alice-sub",
            event_type=AuditEventType.INPUT_RECEIVED,
            payload_hash=hash_payload({"v": version}),
            hash_version=version,
            metadata_hash=metadata_hash,
            metadata_json={},
            previous_hash=previous,
            record_hash="",
        )
        row.record_hash = compute_record_hash(
            record_id=record_id,
            timestamp=moment,
            actor_id="alice-sub",
            event_type=str(AuditEventType.INPUT_RECEIVED),
            payload_hash=row.payload_hash,
            previous_hash=previous,
            hash_version=version,
            metadata_hash=metadata_hash,
        )
        session.add(row)
        previous = row.record_hash
    await session.flush()

    agent_row = await append_audit_event(
        session,
        actor_id="service-account-id",
        tenant_id="acme",
        actor_type="agent",
        agent_id="bastion-agent-analyst",
        owner_sub="alice-sub",
        event_type=AuditEventType.TOOL_EXECUTED,
        payload={"tool": "read_file"},
        timestamp=moment + timedelta(seconds=1),
    )
    await session.flush()
    assert agent_row.hash_version == 3

    assert (await verify_audit_chain(session)).ok

    await disable_audit_guard(session)
    await session.execute(
        update(AuditLog).where(AuditLog.id == agent_row.id).values(owner_sub="mallory-sub")
    )
    await enable_audit_guard(session)
    result = await verify_audit_chain(session)
    assert not result.ok
