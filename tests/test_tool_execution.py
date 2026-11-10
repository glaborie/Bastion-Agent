"""Guarded tool execution state machine: suspend, approve, resume (ADR-010)."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agent.tools.catalog import CatalogTool, get_tool_catalog, override_tool_catalog
from agent.tools.decorator import (
    TOOL_NOT_IN_CATALOG_CODE,
    AgentContext,
    ToolAuthorizationError,
    ToolNotInCatalogError,
    ToolStatus,
    get_tool,
    tool,
    unregister_tool,
)
from agent.tools.execution import (
    ApprovalExecutionError,
    approved_ticket_ids,
    expire_stale_approvals,
    request_tool_execution,
    resume_approved_tool,
    verify_ticket_token,
)
from db.audit import verify_audit_chain
from db.models import (
    ApprovalStatus,
    AuditEventType,
    AuditLog,
    PendingApproval,
    fingerprint_request,
    hash_approval_token,
    utcnow,
)
from gateway.approvals import ApprovalDecisionError, decide_ticket
from settings import reset_settings_cache
from tests.conftest import requires_database

pytestmark = requires_database

ARGUMENTS = {"path": "reports/q3.txt", "content": "revenue"}


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    monkeypatch.setenv("TOOL_WORKSPACE_ROOT", str(root))
    reset_settings_cache()
    try:
        yield root
    finally:
        reset_settings_cache()


@pytest.fixture
def failing_tool():
    @tool(
        name="test_failing_write",
        description="Always fails (test fixture).",
        read_only=False,
        required_role="operator",
    )
    async def failing_write(path: str, context: AgentContext) -> dict[str, str]:
        raise RuntimeError("tool exploded")

    entry = CatalogTool(
        name="test_failing_write",
        description="Always fails (test fixture).",
        read_only=False,
        required_role="operator",
        require_approval=True,
        arguments={"path": {"type": "string", "required": True}},
    )
    try:
        # Gate 1 is enforced in the execution state machine, so a fixture tool
        # must also be approved by the catalog it runs under.
        with override_tool_catalog(extra={entry.name: entry}):
            yield get_tool("test_failing_write")
    finally:
        unregister_tool("test_failing_write")


def context(actor: str = "alice", roles: tuple[str, ...] = ("operator",)) -> AgentContext:
    return AgentContext(actor_id=actor, roles=frozenset(roles), session_id="sess-tool")


@pytest.fixture
def worker_db(db_engine, monkeypatch):
    """Point the worker's ``session_scope`` at the disposable test database."""
    from db import session as db_session

    monkeypatch.setattr(db_session, "_engine", db_engine)
    monkeypatch.setattr(db_session, "_session_factory", None)
    yield db_engine
    monkeypatch.setattr(db_session, "_session_factory", None)


async def events(session: AsyncSession) -> list[AuditLog]:
    statement = select(AuditLog).order_by(AuditLog.id.asc())
    return list((await session.execute(statement)).scalars())


async def request_write(session: AsyncSession, *, now=None):
    return await request_tool_execution(
        session,
        tool_name="execute_file_write",
        arguments=dict(ARGUMENTS),
        context=context(),
        now=now,
    )


async def approve(session: AsyncSession, ticket_id: str, *, actor: str = "bob") -> None:
    await decide_ticket(
        session,
        ticket_id=uuid.UUID(ticket_id),
        actor_id=actor,
        actor_roles={"operator"},
        action="approve",
    )


# ---------------------------------------------------------------------------
# Read-only path
# ---------------------------------------------------------------------------


async def test_read_only_tool_executes_immediately(session: AsyncSession, workspace) -> None:
    result = await request_tool_execution(
        session,
        tool_name="read_system_status",
        arguments={},
        context=context(),
    )

    assert result.status is ToolStatus.EXECUTED
    assert result.executed
    assert result.output["requested_by"] == "alice"

    tickets = list((await session.execute(select(PendingApproval))).scalars())
    assert not tickets
    assert [event.event_type for event in await events(session)] == [
        AuditEventType.TOOL_REQUESTED,
        AuditEventType.TOOL_EXECUTED,
    ]
    assert (await verify_audit_chain(session)).ok


# ---------------------------------------------------------------------------
# Suspension
# ---------------------------------------------------------------------------


async def test_write_tool_suspends_and_binds_the_request(session: AsyncSession, workspace) -> None:
    result = await request_write(session)

    assert result.status is ToolStatus.APPROVAL_PENDING
    assert not result.executed
    assert result.ticket_id is not None
    assert result.approval_token is not None
    assert result.expires_at is not None
    remaining = (result.expires_at - utcnow()).total_seconds()
    assert 880 <= remaining <= 905

    ticket = await session.get(PendingApproval, uuid.UUID(result.ticket_id))
    assert ticket is not None
    assert ticket.status is ApprovalStatus.PENDING
    assert ticket.initiator_id == "alice"
    assert ticket.required_role == "operator"
    assert ticket.request_fingerprint == fingerprint_request("execute_file_write", ARGUMENTS)
    assert ticket.approval_token_hash == hash_approval_token(result.approval_token)
    assert verify_ticket_token(ticket, result.approval_token)
    assert not verify_ticket_token(ticket, "v1.not-the-token")

    assert not (workspace / "reports/q3.txt").exists()

    records = await events(session)
    assert [event.event_type for event in records] == [
        AuditEventType.TOOL_REQUESTED,
        AuditEventType.APPROVAL_REQUESTED,
    ]
    # Argument *values* must never reach the ledger.
    rendered = json.dumps([record.metadata_json for record in records])
    assert "revenue" not in rendered
    assert "reports/q3.txt" not in rendered
    assert (await verify_audit_chain(session)).ok


async def test_role_without_the_required_grant_is_denied(session: AsyncSession, workspace) -> None:
    with pytest.raises(ToolAuthorizationError):
        await request_tool_execution(
            session,
            tool_name="execute_file_write",
            arguments=dict(ARGUMENTS),
            context=context("carol", ("analyst",)),
        )

    assert not list((await session.execute(select(PendingApproval))).scalars())
    records = await events(session)
    assert [record.event_type for record in records] == [AuditEventType.TOOL_REQUESTED]
    assert records[0].metadata_json["outcome"] == "denied"
    assert (await verify_audit_chain(session)).ok


async def test_initiator_cannot_approve_their_own_ticket(session: AsyncSession, workspace) -> None:
    pending = await request_write(session)
    assert pending.ticket_id is not None

    with pytest.raises(ApprovalDecisionError) as info:
        await approve(session, pending.ticket_id, actor="alice")
    assert info.value.code == "self_approval"

    ticket = await session.get(PendingApproval, uuid.UUID(pending.ticket_id))
    assert ticket is not None
    assert ticket.status is ApprovalStatus.PENDING
    assert ticket.approver_id is None
    assert not (workspace / "reports/q3.txt").exists()


# ---------------------------------------------------------------------------
# Resume
# ---------------------------------------------------------------------------


async def test_resume_after_approval_executes_exactly_once(
    session: AsyncSession, workspace
) -> None:
    pending = await request_write(session)
    assert pending.ticket_id is not None
    await approve(session, pending.ticket_id)

    resumed = await resume_approved_tool(session, ticket_id=pending.ticket_id)
    assert resumed.status is ToolStatus.EXECUTED
    assert resumed.output["path"] == "reports/q3.txt"
    assert (workspace / "reports/q3.txt").read_text() == "revenue"

    ticket = await session.get(PendingApproval, uuid.UUID(pending.ticket_id))
    assert ticket is not None
    assert ticket.status is ApprovalStatus.EXECUTED
    assert ticket.executed_at is not None

    again = await resume_approved_tool(session, ticket_id=pending.ticket_id)
    assert again.status is ToolStatus.EXECUTED
    assert again.output is None

    records = await events(session)
    types = [record.event_type for record in records]
    assert types.count(AuditEventType.TOOL_EXECUTED) == 1
    assert AuditEventType.APPROVAL_GRANTED in types
    assert (await verify_audit_chain(session)).ok


async def test_resume_before_approval_is_refused(session: AsyncSession, workspace) -> None:
    pending = await request_write(session)
    assert pending.ticket_id is not None

    with pytest.raises(ApprovalExecutionError) as info:
        await resume_approved_tool(session, ticket_id=pending.ticket_id)
    assert info.value.code == "not_approved"
    assert not (workspace / "reports/q3.txt").exists()


async def test_rejected_ticket_is_not_executed(session: AsyncSession, workspace) -> None:
    pending = await request_write(session)
    assert pending.ticket_id is not None
    await decide_ticket(
        session,
        ticket_id=uuid.UUID(pending.ticket_id),
        actor_id="bob",
        actor_roles={"operator"},
        action="reject",
        reason="not in scope",
    )

    result = await resume_approved_tool(session, ticket_id=pending.ticket_id)
    assert result.status is ToolStatus.REJECTED
    assert not (workspace / "reports/q3.txt").exists()
    assert AuditEventType.APPROVAL_REJECTED in [
        record.event_type for record in await events(session)
    ]


async def test_expired_ticket_is_closed_without_executing(session: AsyncSession, workspace) -> None:
    pending = await request_write(session, now=utcnow() - timedelta(hours=2))
    assert pending.ticket_id is not None

    result = await resume_approved_tool(session, ticket_id=pending.ticket_id)
    assert result.status is ToolStatus.EXPIRED

    ticket = await session.get(PendingApproval, uuid.UUID(pending.ticket_id))
    assert ticket is not None
    assert ticket.status is ApprovalStatus.EXPIRED
    assert not (workspace / "reports/q3.txt").exists()


async def test_tampered_arguments_fail_closed_and_flag_an_incident(
    session: AsyncSession, workspace
) -> None:
    pending = await request_write(session)
    assert pending.ticket_id is not None
    await approve(session, pending.ticket_id)

    ticket = await session.get(PendingApproval, uuid.UUID(pending.ticket_id))
    assert ticket is not None
    ticket.tool_arguments = {"path": "exfiltrate.txt", "content": "secret"}
    await session.flush()

    with pytest.raises(ApprovalExecutionError) as info:
        await resume_approved_tool(session, ticket_id=pending.ticket_id)
    assert info.value.code == "fingerprint_mismatch"

    refreshed = await session.get(PendingApproval, uuid.UUID(pending.ticket_id))
    assert refreshed is not None
    assert refreshed.status is ApprovalStatus.FAILED
    types = [record.event_type for record in await events(session)]
    assert AuditEventType.SECURITY_INCIDENT in types
    assert not (workspace / "exfiltrate.txt").exists()


async def test_tool_failure_marks_the_ticket_failed(
    session: AsyncSession, workspace, failing_tool
) -> None:
    pending = await request_tool_execution(
        session,
        tool_name="test_failing_write",
        arguments={"path": "boom.txt"},
        context=context(),
    )
    assert pending.status is ToolStatus.APPROVAL_PENDING
    assert pending.ticket_id is not None
    await approve(session, pending.ticket_id)

    result = await resume_approved_tool(session, ticket_id=pending.ticket_id)
    assert result.status is ToolStatus.FAILED
    assert result.error == "ToolInvocationError"

    ticket = await session.get(PendingApproval, uuid.UUID(pending.ticket_id))
    assert ticket is not None
    assert ticket.status is ApprovalStatus.FAILED

    executed = [
        record
        for record in await events(session)
        if record.event_type is AuditEventType.TOOL_EXECUTED
    ]
    assert len(executed) == 1
    assert executed[0].metadata_json["outcome"] == "failed"
    assert executed[0].metadata_json["error_type"] == "ToolInvocationError"
    assert (await verify_audit_chain(session)).ok


# ---------------------------------------------------------------------------
# Sweeps
# ---------------------------------------------------------------------------


async def test_expire_sweep_closes_only_lapsed_tickets(session: AsyncSession, workspace) -> None:
    old = await request_write(session, now=utcnow() - timedelta(hours=1))
    fresh = await request_write(session)

    assert await expire_stale_approvals(session) == 1

    old_ticket = await session.get(PendingApproval, uuid.UUID(str(old.ticket_id)))
    fresh_ticket = await session.get(PendingApproval, uuid.UUID(str(fresh.ticket_id)))
    assert old_ticket is not None and old_ticket.status is ApprovalStatus.EXPIRED
    assert fresh_ticket is not None and fresh_ticket.status is ApprovalStatus.PENDING


async def test_approved_ticket_ids_drives_the_safety_net(session: AsyncSession, workspace) -> None:
    pending = await request_write(session)
    assert pending.ticket_id is not None
    assert await approved_ticket_ids(session) == []

    await approve(session, pending.ticket_id)
    assert await approved_ticket_ids(session) == [uuid.UUID(pending.ticket_id)]

    await resume_approved_tool(session, ticket_id=pending.ticket_id)
    assert await approved_ticket_ids(session) == []


async def test_unknown_and_malformed_tickets_are_rejected(session: AsyncSession) -> None:
    with pytest.raises(ApprovalExecutionError) as missing:
        await resume_approved_tool(session, ticket_id=uuid.uuid4())
    assert missing.value.code == "not_found"

    with pytest.raises(ApprovalExecutionError) as malformed:
        await resume_approved_tool(session, ticket_id="not-a-uuid")
    assert malformed.value.code == "invalid_ticket"


# ---------------------------------------------------------------------------
# Gate 1: the approved tool catalog
# ---------------------------------------------------------------------------


async def test_unapproved_tool_is_rejected_before_a_ticket(
    session: AsyncSession, workspace
) -> None:
    @tool(
        name="test_rogue_write",
        description="registered in code, never approved",
        read_only=False,
        required_role="operator",
    )
    async def rogue_write(path: str, context: AgentContext) -> None: ...

    try:
        with pytest.raises(ToolNotInCatalogError) as info:
            await request_tool_execution(
                session,
                tool_name="test_rogue_write",
                arguments={"path": "rogue.txt"},
                context=context(),
            )
        assert info.value.code == -32003

        assert not list((await session.execute(select(PendingApproval))).scalars())
        records = await events(session)
        assert [record.event_type for record in records] == [AuditEventType.TOOL_REQUESTED]
        assert records[0].metadata_json["outcome"] == "not_in_catalog"
        assert records[0].metadata_json["code"] == -32003
        assert (await verify_audit_chain(session)).ok
    finally:
        unregister_tool("test_rogue_write")


async def test_catalog_can_require_approval_for_a_read_only_tool(
    session: AsyncSession, workspace
) -> None:
    @tool(
        name="test_readonly_report",
        description="read-only but gated by the catalog",
        read_only=True,
        required_role="operator",
    )
    async def readonly_report(context: AgentContext) -> dict[str, str]:
        return {"status": "ok"}

    entry = CatalogTool(
        name="test_readonly_report",
        description="read-only but gated by the catalog",
        read_only=True,
        required_role="operator",
        require_approval=True,
        arguments={},
    )
    try:
        with override_tool_catalog(extra={entry.name: entry}):
            pending = await request_tool_execution(
                session,
                tool_name="test_readonly_report",
                arguments={},
                context=context(),
            )
            assert pending.status is ToolStatus.APPROVAL_PENDING
            assert pending.ticket_id is not None
            await approve(session, pending.ticket_id)
            result = await resume_approved_tool(session, ticket_id=pending.ticket_id)
        assert result.status is ToolStatus.EXECUTED
        assert result.output == {"status": "ok"}
    finally:
        unregister_tool("test_readonly_report")


async def test_resume_refuses_a_tool_that_left_the_catalog(
    session: AsyncSession, workspace
) -> None:
    pending = await request_write(session)
    assert pending.ticket_id is not None
    await approve(session, pending.ticket_id)

    catalog = get_tool_catalog()
    with override_tool_catalog(catalog.without("execute_file_write")):
        result = await resume_approved_tool(session, ticket_id=pending.ticket_id)

    assert result.status is ToolStatus.FAILED
    assert result.error == "tool_not_approved"
    ticket = await session.get(PendingApproval, uuid.UUID(pending.ticket_id))
    assert ticket is not None and ticket.status is ApprovalStatus.FAILED
    assert AuditEventType.SECURITY_INCIDENT in [
        record.event_type for record in await events(session)
    ]
    assert not (workspace / "reports/q3.txt").exists()
    assert (await verify_audit_chain(session)).ok


async def test_worker_commits_a_catalog_refusal_after_the_request_rolls_back(
    worker_db, workspace
) -> None:
    """Gate 1 must outlive the request transaction it aborts (ADR-009).

    ``execute_tool_job`` runs the guard inside ``session_scope``, which rolls
    back when the guard raises — taking the in-transaction audit row with it.
    The worker re-records the refusal in its own transaction, so the ledger
    always shows what was denied.
    """
    from agent.runtime import execute_tool_job

    @tool(
        name="test_rogue_write",
        description="registered in code, never approved",
        read_only=False,
        required_role="operator",
    )
    async def rogue_write(path: str, context: AgentContext) -> None: ...

    try:
        result = await execute_tool_job(
            {"job_id": "test-job"},
            tool_name="test_rogue_write",
            actor_id="alice",
            roles=["operator"],
            session_id="sess-gate1",
            arguments={"path": "rogue.txt"},
        )
    finally:
        unregister_tool("test_rogue_write")

    assert result["status"] == "unknown_tool"
    assert result["code"] == TOOL_NOT_IN_CATALOG_CODE == -32003

    factory = async_sessionmaker(worker_db, expire_on_commit=False)
    async with factory() as fresh:
        records = list((await fresh.execute(select(AuditLog).order_by(AuditLog.id))).scalars())
        tickets = list((await fresh.execute(select(PendingApproval))).scalars())
        assert (await verify_audit_chain(fresh)).ok

    assert not tickets
    assert [record.event_type for record in records] == [AuditEventType.TOOL_REQUESTED]
    assert records[0].actor_id == "alice"
    assert records[0].session_id == "sess-gate1"
    assert records[0].metadata_json == {
        "tool": "test_rogue_write",
        "outcome": "not_in_catalog",
        "code": -32003,
        "argument_keys": ["path"],
    }


# ---------------------------------------------------------------------------
# Worker spans
# ---------------------------------------------------------------------------


def capture_worker_spans(monkeypatch: pytest.MonkeyPatch) -> InMemorySpanExporter:
    """Give the worker tracer an in-memory exporter instead of an OTLP one."""
    from agent import runtime

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(runtime, "_tracer", provider.get_tracer("test-worker"))
    return exporter


async def test_worker_span_records_the_suspension_ticket(
    worker_db, workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worker half of four-eyes must be visible, and must not carry arguments.

    The span is named after the tool and joined to the ledger by ticket id; the
    argument values stay hashed in the audit row, because traces leave the host.
    """
    from agent.runtime import execute_tool_job

    exporter = capture_worker_spans(monkeypatch)
    result = await execute_tool_job(
        {"job_id": "test-span-job"},
        tool_name="execute_file_write",
        actor_id="alice",
        roles=["operator"],
        session_id="sess-span",
        arguments=dict(ARGUMENTS),
    )

    spans = exporter.get_finished_spans()
    assert result["status"] == "approval_pending"
    assert [span.name for span in spans] == ["tool.execute execute_file_write"]
    attributes = dict(spans[0].attributes or {})
    assert attributes["bastion.tool.name"] == "execute_file_write"
    assert attributes["bastion.tool.status"] == "approval_pending"
    assert attributes["bastion.audit.session_id"] == "sess-span"
    assert attributes["bastion.approval.ticket_id"] == result["ticket_id"]
    assert "reports/q3.txt" not in json.dumps(attributes)
    assert "revenue" not in json.dumps(attributes)


async def test_resume_span_records_the_executed_ticket(
    worker_db, workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resumed ticket carries the same ticket id the gateway decision does."""
    from agent.runtime import execute_tool_job, resume_tool_job

    exporter = capture_worker_spans(monkeypatch)
    pending = await execute_tool_job(
        {"job_id": "test-span-job"},
        tool_name="execute_file_write",
        actor_id="alice",
        roles=["operator"],
        session_id="sess-span",
        arguments=dict(ARGUMENTS),
    )
    assert pending["ticket_id"] is not None

    factory = async_sessionmaker(worker_db, expire_on_commit=False)
    async with factory() as approver:
        await approve(approver, pending["ticket_id"])
        await approver.commit()

    exporter.clear()
    result = await resume_tool_job({"job_id": "test-resume-job"}, ticket_id=pending["ticket_id"])

    spans = exporter.get_finished_spans()
    assert result["status"] == "executed"
    assert [span.name for span in spans] == ["tool.resume"]
    attributes = dict(spans[0].attributes or {})
    assert attributes["bastion.approval.ticket_id"] == pending["ticket_id"]
    assert attributes["bastion.tool.status"] == "executed"
    assert (workspace / "reports/q3.txt").read_text() == "revenue"


async def test_resume_span_marks_a_ticket_that_is_not_ready(
    worker_db, workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal is a status, not a silent empty span."""
    from agent.runtime import execute_tool_job, resume_tool_job

    exporter = capture_worker_spans(monkeypatch)
    pending = await execute_tool_job(
        {"job_id": "test-span-job"},
        tool_name="execute_file_write",
        actor_id="alice",
        roles=["operator"],
        session_id="sess-span",
        arguments=dict(ARGUMENTS),
    )
    exporter.clear()

    result = await resume_tool_job({"job_id": "test-resume-job"}, ticket_id=pending["ticket_id"])

    spans = exporter.get_finished_spans()
    assert result["status"] == "not_approved"
    attributes = dict(spans[0].attributes or {})
    assert attributes["bastion.tool.status"] == "not_approved"
    assert attributes["error.type"] == "ApprovalExecutionError"
    assert not (workspace / "reports/q3.txt").exists()


async def test_read_only_worker_span_has_no_ticket(
    worker_db, workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No suspension means no approval attribute to misinterpret downstream."""
    from agent.runtime import execute_tool_job

    exporter = capture_worker_spans(monkeypatch)
    result = await execute_tool_job(
        {"job_id": "test-read-job"},
        tool_name="read_system_status",
        actor_id="alice",
        roles=["operator"],
        session_id="sess-read",
        arguments={},
    )

    assert result["status"] == "executed"
    attributes = dict(exporter.get_finished_spans()[0].attributes or {})
    assert attributes["bastion.tool.status"] == "executed"
    assert "bastion.approval.ticket_id" not in attributes
    assert "bastion.tool.code" not in attributes
