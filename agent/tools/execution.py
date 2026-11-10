"""Guarded tool execution: immediate reads, four-eyes suspension and resume.

The state machine lives here so the gateway and the ARQ worker share one
implementation and one audit trail (ADR-003, ADR-010)::

    request ──read_only──▶ execute ──▶ EXECUTED
        └────mutating───▶ PENDING ──approve──▶ APPROVED ──resume──▶ EXECUTED
                             └────reject────▶ REJECTED
                             └────timeout───▶ EXPIRED

Every transition appends a hash-chained audit record in the **same
transaction** as the state change. Argument values are never written to the
ledger or to logs: ``payload_hash`` covers them, ``metadata_json`` carries only
keys, hashes and identifiers.
"""

from __future__ import annotations

import hmac
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Final, NoReturn

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agent.tools.catalog import CatalogTool, get_tool_catalog
from agent.tools.decorator import (
    AgentContext,
    ToolAuthorizationError,
    ToolCatalogDriftError,
    ToolCatalogUnavailableError,
    ToolDefinition,
    ToolError,
    ToolExecutionResult,
    ToolNotFoundError,
    ToolNotInCatalogError,
    ToolStatus,
    get_tool,
)
from db.audit import append_audit_event
from db.models import (
    ApprovalStatus,
    AuditEventType,
    PendingApproval,
    fingerprint_request,
    hash_approval_token,
    sign_approval_token,
    utcnow,
    verify_approval_token,
)
from settings import get_settings

logger = logging.getLogger(__name__)

#: Actor recorded for events the runtime generates on its own behalf.
SYSTEM_ACTOR: Final[str] = "system:tool-runtime"

_TERMINAL_RESULTS: Final[dict[ApprovalStatus, ToolStatus]] = {
    ApprovalStatus.EXECUTED: ToolStatus.EXECUTED,
    ApprovalStatus.REJECTED: ToolStatus.REJECTED,
    ApprovalStatus.EXPIRED: ToolStatus.EXPIRED,
    ApprovalStatus.FAILED: ToolStatus.FAILED,
}


#: ``outcome`` recorded on a ``TOOL_REQUESTED`` row for each refusal class.
_FIXED_OUTCOMES: Final[tuple[tuple[type[ToolError], str], ...]] = (
    (ToolAuthorizationError, "denied"),
    (ToolNotFoundError, "not_registered"),
    (ToolNotInCatalogError, "not_in_catalog"),
    (ToolCatalogDriftError, "catalog_drift"),
    (ToolCatalogUnavailableError, "catalog_unavailable"),
)


class ApprovalExecutionError(ToolError):
    """The ticket cannot be resumed in its current state."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def refusal_outcome(error: ToolError) -> str:
    """The stable ledger outcome for a refused tool call."""
    for error_type, outcome in _FIXED_OUTCOMES:
        if isinstance(error, error_type):
            return outcome
    return "refused"


async def record_tool_refusal(
    session: AsyncSession,
    *,
    context: AgentContext,
    tool_name: str,
    error: ToolError,
    arguments: dict[str, Any] | None = None,
    moment: datetime | None = None,
) -> None:
    """Append one ``TOOL_REQUESTED`` row describing a refused call.

    A refusal ends the unit of work, so the worker job calls this again in a
    dedicated transaction: the guard writes the row inside the request
    transaction (for callers that manage it), which is rolled back when the
    guard raises. Recording the outcome twice is impossible — the first write
    never commits.
    """
    metadata: dict[str, Any] = {
        "tool": tool_name,
        "outcome": refusal_outcome(error),
    }
    code = getattr(error, "code", None)
    if code is not None:
        metadata["code"] = code
    required_role = getattr(error, "required_role", None)
    if required_role:
        metadata["required_role"] = required_role
    if arguments is not None:
        metadata["argument_keys"] = sorted(arguments)

    payload: dict[str, Any] = {"tool": tool_name}
    if arguments is not None:
        payload["arguments"] = arguments
    await append_audit_event(
        session,
        actor_id=context.actor_id,
        event_type=AuditEventType.TOOL_REQUESTED,
        session_id=context.session_id,
        payload=payload,
        metadata_json=metadata,
        timestamp=moment or utcnow(),
    )
    await session.flush()


async def request_tool_execution(
    session: AsyncSession,
    *,
    tool_name: str,
    arguments: dict[str, Any] | None,
    context: AgentContext,
    now: datetime | None = None,
) -> ToolExecutionResult:
    """Authorize, execute or suspend one tool call.

    Read-only tools execute immediately when RBAC permits. Mutating tools create
    a :class:`PendingApproval` bound to the exact arguments and return
    ``approval_pending`` with the ticket id and one-time capability token.
    """
    definition = get_tool(tool_name)
    moment = now or utcnow()

    # Gate 1: the tool must be in the approved catalog before its arguments are
    # parsed, before RBAC is consulted and before a ticket could be created.
    entry = await _authorize_catalog(session, definition, context, moment)
    cleaned = definition.validate_arguments(arguments)

    if not definition.permits(context.roles):
        await _deny_rbac(session, definition, cleaned, context, moment)

    await _record_accepted(session, definition, cleaned, context, moment)

    if definition.read_only and not entry.require_approval:
        return await _execute_now(session, definition, cleaned, context, moment)

    return await _suspend(session, definition, cleaned, context, moment)


async def resume_approved_tool(
    session: AsyncSession,
    *,
    ticket_id: uuid.UUID | str,
    now: datetime | None = None,
) -> ToolExecutionResult:
    """Resume one approved ticket exactly once.

    The ticket row is locked for the duration, so a concurrent retry blocks and
    then observes ``EXECUTED`` instead of running the tool twice. Execution is
    at-least-once across a worker crash: the row stays ``APPROVED`` until the
    tool returns, so a crash re-runs the call on the next sweep. Tools must be
    idempotent or tolerate retries.
    """
    moment = now or utcnow()
    identifier = _coerce_uuid(ticket_id)
    ticket = (
        await session.execute(
            select(PendingApproval).where(PendingApproval.ticket_id == identifier).with_for_update()
        )
    ).scalar_one_or_none()
    if ticket is None:
        raise ApprovalExecutionError("not_found", "approval ticket not found")

    if ticket.status in _TERMINAL_RESULTS:
        return ToolExecutionResult(
            status=_TERMINAL_RESULTS[ticket.status], tool_name=ticket.tool_name
        )

    if ticket.status is ApprovalStatus.PENDING:
        if ticket.token_expires_at > moment:
            raise ApprovalExecutionError("not_approved", "the ticket is still awaiting a decision")
        ticket.status = ApprovalStatus.EXPIRED
        await session.flush()
        logger.info("Approval expired", extra={"ticket_id": str(ticket.ticket_id)})
        return ToolExecutionResult(status=ToolStatus.EXPIRED, tool_name=ticket.tool_name)

    # From here the ticket is APPROVED.
    if not ticket.approver_id or ticket.approver_id == ticket.initiator_id:
        await _record_incident(session, ticket, "approver_missing_or_is_initiator")
        await _mark_failed(session, ticket, moment)
        raise ApprovalExecutionError(
            "four_eyes_violation", "ticket was not approved by a second operator"
        )

    supplied = dict(ticket.tool_arguments or {})
    recomputed = fingerprint_request(ticket.tool_name, supplied)
    if not hmac.compare_digest(recomputed, ticket.request_fingerprint):
        await _record_incident(session, ticket, "request_fingerprint_mismatch")
        await _mark_failed(session, ticket, moment)
        raise ApprovalExecutionError(
            "fingerprint_mismatch",
            "stored arguments no longer match the approved request",
        )

    try:
        definition = get_tool(ticket.tool_name)
    except ToolNotFoundError:
        await _record_incident(session, ticket, "tool_no_longer_registered")
        await _mark_failed(session, ticket, moment)
        return ToolExecutionResult(
            status=ToolStatus.FAILED, tool_name=ticket.tool_name, error="tool_not_registered"
        )

    # Gate 1 is re-checked at execution time: approval does not outlive the
    # catalog. A tool removed from (or changed in) the allow-list after the
    # ticket was approved must not run.
    if (failure := await _authorize_resume(session, ticket, definition, moment)) is not None:
        return ToolExecutionResult(
            status=ToolStatus.FAILED, tool_name=ticket.tool_name, error=failure
        )

    context = AgentContext(
        actor_id=ticket.initiator_id,
        roles=frozenset({ticket.required_role}),
        session_id=ticket.session_id,
        request_id=f"ticket:{ticket.ticket_id}",
    )
    started = time.perf_counter()
    try:
        output = await definition.invoke(supplied, context)
    # A tool failure must mark the ticket FAILED and keep the worker alive;
    # CancelledError is a BaseException and still propagates.
    except Exception as exc:  # pylint: disable=broad-exception-caught
        duration_ms = _elapsed_ms(started)
        await _mark_failed(session, ticket, moment)
        await _record_execution(
            session,
            definition,
            actor_id=ticket.initiator_id,
            session_id=ticket.session_id,
            moment=moment,
            outcome="failed",
            duration_ms=duration_ms,
            ticket_id=ticket.ticket_id,
            error_type=type(exc).__name__,
        )
        await session.flush()
        logger.warning(
            "Approved tool failed",
            extra={
                "tool": definition.name,
                "ticket_id": str(ticket.ticket_id),
                "error_type": type(exc).__name__,
            },
        )
        return ToolExecutionResult(
            status=ToolStatus.FAILED,
            tool_name=definition.name,
            error=type(exc).__name__,
        )

    duration_ms = _elapsed_ms(started)
    ticket.status = ApprovalStatus.EXECUTED
    ticket.executed_at = moment
    await _record_execution(
        session,
        definition,
        actor_id=ticket.initiator_id,
        session_id=ticket.session_id,
        moment=moment,
        outcome="ok",
        duration_ms=duration_ms,
        ticket_id=ticket.ticket_id,
        approver_id=ticket.approver_id,
    )
    await session.flush()
    logger.info(
        "Approved tool executed",
        extra={
            "tool": definition.name,
            "ticket_id": str(ticket.ticket_id),
            "duration_ms": duration_ms,
        },
    )
    return ToolExecutionResult(status=ToolStatus.EXECUTED, tool_name=definition.name, output=output)


async def expire_stale_approvals(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 500,
) -> int:
    """Mark open tickets whose approval window has closed as ``EXPIRED``."""
    moment = now or utcnow()
    if limit <= 0:
        raise ValueError("limit must be positive")
    statement = (
        select(PendingApproval)
        .where(
            PendingApproval.status == ApprovalStatus.PENDING,
            PendingApproval.token_expires_at <= moment,
        )
        .order_by(PendingApproval.token_expires_at.asc())
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    tickets = list((await session.execute(statement)).scalars())
    for ticket in tickets:
        ticket.status = ApprovalStatus.EXPIRED
    if tickets:
        await session.flush()
        logger.info("Expired stale approval tickets", extra={"count": len(tickets)})
    return len(tickets)


async def approved_ticket_ids(
    session: AsyncSession, *, limit: int = 50, older_than: datetime | None = None
) -> list[uuid.UUID]:
    """Approved tickets still awaiting execution (cron safety-net input)."""
    if limit <= 0:
        raise ValueError("limit must be positive")
    conditions = [PendingApproval.status == ApprovalStatus.APPROVED]
    if older_than is not None:
        conditions.append(PendingApproval.decided_at <= older_than)
    statement = (
        select(PendingApproval.ticket_id)
        .where(*conditions)
        .order_by(PendingApproval.decided_at.asc().nulls_first())
        .limit(limit)
    )
    return list((await session.execute(statement)).scalars())


def verify_ticket_token(ticket: PendingApproval, token: str) -> bool:
    """Check a capability token against a persisted ticket (constant time)."""
    settings = get_settings()
    if not hmac.compare_digest(hash_approval_token(token), ticket.approval_token_hash):
        return False
    return verify_approval_token(
        token=token,
        ticket_id=ticket.ticket_id,
        request_fingerprint=ticket.request_fingerprint,
        expires_at=ticket.token_expires_at,
        secret=settings.approval_hmac_secret.get_secret_value(),
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _deny_rbac(
    session: AsyncSession,
    definition: ToolDefinition,
    arguments: dict[str, Any],
    context: AgentContext,
    moment: datetime,
) -> NoReturn:
    """Record a role-denied call in the ledger, then raise."""
    error = ToolAuthorizationError(definition.name, definition.required_role or "")
    await record_tool_refusal(
        session,
        context=context,
        tool_name=definition.name,
        error=error,
        arguments=arguments,
        moment=moment,
    )
    logger.warning(
        "Tool call denied by RBAC",
        extra={
            "tool": definition.name,
            "actor_id": context.actor_id,
            "required_role": definition.required_role,
        },
    )
    raise error


async def _authorize_resume(
    session: AsyncSession,
    ticket: PendingApproval,
    definition: ToolDefinition,
    moment: datetime,
) -> str | None:
    """Re-check Gate 1 for an approved ticket; return a failure code or None."""
    try:
        entry = get_tool_catalog().authorize(definition)
    except ToolError:
        await _record_incident(session, ticket, "tool_no_longer_approved")
        await _mark_failed(session, ticket, moment)
        return "tool_not_approved"
    if entry.required_role != ticket.required_role:
        await _record_incident(session, ticket, "required_role_changed")
        await _mark_failed(session, ticket, moment)
        return "policy_changed"
    return None


async def _record_accepted(
    session: AsyncSession,
    definition: ToolDefinition,
    arguments: dict[str, Any],
    context: AgentContext,
    moment: datetime,
) -> None:
    """Record an accepted Gate 1/RBAC decision before it executes."""
    await append_audit_event(
        session,
        actor_id=context.actor_id,
        event_type=AuditEventType.TOOL_REQUESTED,
        session_id=context.session_id,
        payload={"tool": definition.name, "arguments": arguments},
        metadata_json={
            "tool": definition.name,
            "outcome": "accepted",
            "read_only": definition.read_only,
            "required_role": definition.required_role,
            "argument_keys": sorted(arguments),
        },
        timestamp=moment,
    )
    await session.flush()


async def _authorize_catalog(
    session: AsyncSession,
    definition: ToolDefinition,
    context: AgentContext,
    moment: datetime,
) -> CatalogTool:
    """Gate 1: return the catalog entry or audit the refusal and re-raise.

    A rejection is stored in the same hash chain as every other tool event. The
    arguments have not been validated yet, so only the tool name is recorded.
    """
    try:
        return get_tool_catalog().authorize(definition)
    except ToolError as exc:
        await record_tool_refusal(
            session,
            context=context,
            tool_name=definition.name,
            error=exc,
            moment=moment,
        )
        logger.warning(
            "Tool call rejected by the catalog gate",
            extra={
                "tool": definition.name,
                "actor_id": context.actor_id,
                "outcome": refusal_outcome(exc),
            },
        )
        raise


async def _execute_now(
    session: AsyncSession,
    definition: ToolDefinition,
    arguments: dict[str, Any],
    context: AgentContext,
    moment: datetime,
) -> ToolExecutionResult:
    started = time.perf_counter()
    try:
        output = await definition.invoke(arguments, context)
    except Exception as exc:
        await _record_execution(
            session,
            definition,
            actor_id=context.actor_id,
            session_id=context.session_id,
            moment=moment,
            outcome="failed",
            duration_ms=_elapsed_ms(started),
            error_type=type(exc).__name__,
        )
        await session.flush()
        raise
    await _record_execution(
        session,
        definition,
        actor_id=context.actor_id,
        session_id=context.session_id,
        moment=moment,
        outcome="ok",
        duration_ms=_elapsed_ms(started),
    )
    await session.flush()
    return ToolExecutionResult(status=ToolStatus.EXECUTED, tool_name=definition.name, output=output)


async def _suspend(
    session: AsyncSession,
    definition: ToolDefinition,
    arguments: dict[str, Any],
    context: AgentContext,
    moment: datetime,
) -> ToolExecutionResult:
    settings = get_settings()
    expires_at = PendingApproval.expiry_for(moment, settings.approval_ttl_seconds)
    ticket_id = uuid.uuid4()
    fingerprint = fingerprint_request(definition.name, arguments)
    token = sign_approval_token(
        ticket_id=ticket_id,
        request_fingerprint=fingerprint,
        expires_at=expires_at,
        secret=settings.approval_hmac_secret.get_secret_value(),
    )
    ticket = PendingApproval(
        ticket_id=ticket_id,
        session_id=context.session_id,
        initiator_id=context.actor_id,
        tool_name=definition.name,
        tool_arguments=arguments,
        required_role=definition.required_role or "",
        request_fingerprint=fingerprint,
        approval_token_hash=hash_approval_token(token),
        token_expires_at=expires_at,
        created_at=moment,
    )
    session.add(ticket)
    await session.flush()

    await append_audit_event(
        session,
        actor_id=context.actor_id,
        event_type=AuditEventType.APPROVAL_REQUESTED,
        session_id=context.session_id,
        payload={
            "ticket_id": str(ticket_id),
            "tool": definition.name,
            "request_fingerprint": fingerprint,
        },
        metadata_json={
            "initiator_id": context.actor_id,
            "required_role": definition.required_role,
            "expires_at": expires_at.isoformat(),
            "argument_keys": sorted(arguments),
        },
        timestamp=moment,
    )
    await session.flush()
    logger.info(
        "Tool call suspended for approval",
        extra={
            "tool": definition.name,
            "ticket_id": str(ticket_id),
            "initiator_id": context.actor_id,
        },
    )
    return ToolExecutionResult(
        status=ToolStatus.APPROVAL_PENDING,
        tool_name=definition.name,
        ticket_id=str(ticket_id),
        approval_token=token,
        expires_at=expires_at,
    )


async def _record_execution(
    session: AsyncSession,
    definition: ToolDefinition,
    *,
    actor_id: str,
    session_id: str | None,
    moment: datetime,
    outcome: str,
    duration_ms: int,
    ticket_id: uuid.UUID | None = None,
    error_type: str | None = None,
    approver_id: str | None = None,
) -> None:
    await append_audit_event(
        session,
        actor_id=actor_id,
        event_type=AuditEventType.TOOL_EXECUTED,
        session_id=session_id,
        payload={
            "tool": definition.name,
            "outcome": outcome,
            "ticket_id": str(ticket_id) if ticket_id else None,
        },
        metadata_json={
            "tool": definition.name,
            "outcome": outcome,
            "duration_ms": duration_ms,
            "read_only": definition.read_only,
            "approver_id": approver_id,
            "error_type": error_type,
        },
        timestamp=moment,
    )


async def _record_incident(session: AsyncSession, ticket: PendingApproval, reason: str) -> None:
    await append_audit_event(
        session,
        actor_id=SYSTEM_ACTOR,
        event_type=AuditEventType.SECURITY_INCIDENT,
        session_id=ticket.session_id,
        payload={
            "ticket_id": str(ticket.ticket_id),
            "tool": ticket.tool_name,
            "reason": reason,
        },
        metadata_json={
            "initiator_id": ticket.initiator_id,
            "approver_id": ticket.approver_id,
            "reason": reason,
        },
    )
    logger.error(
        "Approval integrity failure",
        extra={"ticket_id": str(ticket.ticket_id), "reason": reason},
    )


async def _mark_failed(session: AsyncSession, ticket: PendingApproval, moment: datetime) -> None:
    ticket.status = ApprovalStatus.FAILED
    ticket.executed_at = moment
    await session.flush()


def _coerce_uuid(value: uuid.UUID | str) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ApprovalExecutionError("invalid_ticket", "ticket id is not a UUID") from exc


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
