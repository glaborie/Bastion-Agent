"""Approval-queue service shared by the dashboard and the JSON API (ADR-003).

Decisions are made under a row lock so two approvers cannot race, and every
decision appends an audit record in the same transaction. Free-text reasons live
in the approval row only; the audit ledger stores a hash, because it outlives the
DLP vault and must never accumulate free-form PII.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.audit import append_audit_event
from db.models import (
    ApprovalStatus,
    AuditEventType,
    PendingApproval,
    hash_payload,
    utcnow,
)
from gateway.auth.roles import is_satisfied

logger = logging.getLogger(__name__)

DecisionAction = Literal["approve", "reject"]

MAX_REASON_LENGTH = 1024


class ApprovalDecisionError(Exception):
    """A ticket could not be decided; ``code`` maps to an HTTP status."""

    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class ApprovalView:
    ticket_id: str
    tool_name: str
    tool_arguments: dict[str, Any]
    argument_count: int
    initiator_id: str
    required_role: str
    status: str
    token_expires_at: datetime
    expires_in: str
    decidable: bool
    expired: bool


def humanize_remaining(expires_at: datetime, *, now: datetime | None = None) -> str:
    moment = now or utcnow()
    remaining = int((expires_at - moment).total_seconds())
    if remaining <= 0:
        return "expired"
    hours, remainder = divmod(remaining, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def to_view(
    ticket: PendingApproval,
    *,
    viewer_id: str,
    viewer_roles: frozenset[str] | set[str],
    now: datetime | None = None,
) -> ApprovalView:
    moment = now or utcnow()
    expired = ticket.is_expired
    return ApprovalView(
        ticket_id=str(ticket.ticket_id),
        tool_name=ticket.tool_name,
        tool_arguments=dict(ticket.tool_arguments or {}),
        argument_count=len(ticket.tool_arguments or {}),
        initiator_id=ticket.initiator_id,
        required_role=ticket.required_role,
        status=ticket.status.value,
        token_expires_at=ticket.token_expires_at,
        expires_in=humanize_remaining(ticket.token_expires_at, now=moment),
        decidable=(
            ticket.can_be_decided_by(viewer_id) and is_satisfied(viewer_roles, ticket.required_role)
        ),
        expired=expired,
    )


async def list_pending(
    session: AsyncSession,
    *,
    viewer_id: str,
    viewer_roles: frozenset[str] | set[str],
    tenant_id: str,
    limit: int = 100,
    now: datetime | None = None,
) -> list[ApprovalView]:
    """Open tickets, most urgent first.

    A ticket past its window is shown as expired and locked until the worker's
    expiry sweep closes it (at most 30 s); the ledger keeps the history.
    """
    if not 1 <= limit <= 500:
        raise ValueError("limit must be within [1, 500]")
    statement = (
        select(PendingApproval)
        .where(
            PendingApproval.status == ApprovalStatus.PENDING,
            PendingApproval.tenant_id == tenant_id,
        )
        .order_by(PendingApproval.token_expires_at.asc())
        .limit(limit)
    )
    tickets = list((await session.execute(statement)).scalars())
    moment = now or utcnow()
    return [
        to_view(ticket, viewer_id=viewer_id, viewer_roles=viewer_roles, now=moment)
        for ticket in tickets
    ]


@dataclass(frozen=True, slots=True)
class DecisionView:
    """A ticket that has been decided, kept on screen briefly for the record."""

    ticket_id: str
    tool_name: str
    status: str
    initiator_id: str
    approver_id: str
    decided_at: datetime
    decided_ago: str


#: How long a decided ticket stays visible under "Recent decisions".
RECENT_DECISION_MINUTES = 15
RECENT_DECISION_LIMIT = 10


def humanize_elapsed(moment: datetime, *, now: datetime | None = None) -> str:
    elapsed = max(int(((now or utcnow()) - moment).total_seconds()), 0)
    if elapsed < 60:
        return f"{elapsed}s ago"
    minutes, _ = divmod(elapsed, 60)
    if minutes < 60:
        return f"{minutes}m ago"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m ago"


async def list_recently_decided(
    session: AsyncSession,
    *,
    tenant_id: str,
    minutes: int = RECENT_DECISION_MINUTES,
    limit: int = RECENT_DECISION_LIMIT,
    now: datetime | None = None,
) -> list[DecisionView]:
    """Tickets decided within the last ``minutes``, newest first.

    The queue only shows open tickets, so a decision would otherwise erase the
    row before the operator can read (or copy) the ticket id. Keeping decided
    tickets on screen for a short window is the durable fix; the ledger remains
    the authoritative record.
    """
    if minutes <= 0:
        raise ValueError("minutes must be positive")
    if not 1 <= limit <= 100:
        raise ValueError("limit must be within [1, 100]")
    moment = now or utcnow()
    statement = (
        select(PendingApproval)
        .where(
            PendingApproval.tenant_id == tenant_id,
            PendingApproval.status != ApprovalStatus.PENDING,
            PendingApproval.decided_at.is_not(None),
            PendingApproval.decided_at >= moment - timedelta(minutes=minutes),
        )
        .order_by(PendingApproval.decided_at.desc())
        .limit(limit)
    )
    tickets = (await session.execute(statement)).scalars()
    return [
        DecisionView(
            ticket_id=str(ticket.ticket_id),
            tool_name=ticket.tool_name,
            status=ticket.status.value,
            initiator_id=ticket.initiator_id,
            approver_id=ticket.approver_id or "—",
            decided_at=ticket.decided_at or moment,
            decided_ago=humanize_elapsed(ticket.decided_at or moment, now=moment),
        )
        for ticket in tickets
    ]


async def decide_ticket(
    session: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    actor_id: str,
    actor_roles: frozenset[str] | set[str],
    tenant_id: str,
    action: DecisionAction,
    reason: str | None = None,
    now: datetime | None = None,
) -> PendingApproval:
    """Approve or reject one ticket, enforcing every four-eyes invariant."""
    if action not in ("approve", "reject"):
        raise ApprovalDecisionError(
            "invalid_action", "action must be approve or reject", status_code=400
        )
    cleaned_reason = (reason or "").strip() or None
    if cleaned_reason is not None and len(cleaned_reason) > MAX_REASON_LENGTH:
        raise ApprovalDecisionError(
            "invalid_reason",
            f"reason must be at most {MAX_REASON_LENGTH} characters",
            status_code=422,
        )
    if not actor_id:
        raise ApprovalDecisionError("unauthorized", "missing actor identity", status_code=401)

    moment = now or utcnow()
    statement = (
        select(PendingApproval)
        .where(
            PendingApproval.ticket_id == ticket_id,
            PendingApproval.tenant_id == tenant_id,
        )
        .with_for_update()
    )
    ticket = (await session.execute(statement)).scalar_one_or_none()
    if ticket is None:
        raise ApprovalDecisionError("not_found", "approval ticket not found", status_code=404)
    if ticket.initiator_id == actor_id:
        logger.warning(
            "Four-eyes violation blocked",
            extra={"ticket_id": str(ticket_id), "actor_id": actor_id},
        )
        raise ApprovalDecisionError(
            "self_approval",
            "the initiator cannot decide their own ticket (four-eyes principle)",
            status_code=403,
        )
    if ticket.status != ApprovalStatus.PENDING:
        raise ApprovalDecisionError(
            "already_decided",
            f"ticket is already {ticket.status.value}",
            status_code=409,
        )
    if ticket.token_expires_at <= moment:
        raise ApprovalDecisionError(
            "expired",
            "the approval window has closed",
            status_code=409,
        )
    if not is_satisfied(actor_roles, ticket.required_role):
        raise ApprovalDecisionError(
            "role_required",
            f"this ticket requires the {ticket.required_role!r} role",
            status_code=403,
        )

    approved = action == "approve"
    ticket.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
    ticket.approver_id = actor_id
    ticket.decided_at = moment
    ticket.decision_reason = cleaned_reason

    await append_audit_event(
        session,
        actor_id=actor_id,
        tenant_id=ticket.tenant_id,
        event_type=AuditEventType.APPROVAL_GRANTED
        if approved
        else AuditEventType.APPROVAL_REJECTED,
        session_id=ticket.session_id,
        payload={
            "ticket_id": str(ticket.ticket_id),
            "tool": ticket.tool_name,
            "request_fingerprint": ticket.request_fingerprint,
            "action": action,
        },
        metadata_json={
            "initiator_id": ticket.initiator_id,
            "required_role": ticket.required_role,
            "reason_sha256": hash_payload(cleaned_reason) if cleaned_reason else None,
        },
        timestamp=moment,
    )
    await session.flush()
    logger.info(
        "Approval decided",
        extra={
            "ticket_id": str(ticket.ticket_id),
            "action": action,
            "approver_id": actor_id,
            "initiator_id": ticket.initiator_id,
        },
    )
    return ticket


def parse_action(value: str) -> DecisionAction:
    """Normalise a form value, rejecting anything but the two decisions."""
    normalised = (value or "").strip().lower()
    if normalised not in ("approve", "reject"):
        raise ApprovalDecisionError(
            "invalid_action",
            "action must be approve or reject",
            status_code=400,
        )
    return normalised  # type: ignore[return-value]


def utc_isoformat(value: datetime) -> str:
    moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat()
