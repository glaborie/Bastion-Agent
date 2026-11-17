"""Read-only audit-ledger queries used by the dashboard and the API."""

from __future__ import annotations

import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AuditEventType, AuditLog, PayloadEscrow, utcnow

DEFAULT_PAGE_SIZE: Final[int] = 50
MAX_PAGE_SIZE: Final[int] = 200
MAX_TIMELINE_RECORDS: Final[int] = 1000
#: Upper bound for the dashboard's live incident panel.
MAX_INCIDENT_RECORDS: Final[int] = 10
#: Upper bound for the operator handoff queue (ADR-022).
MAX_HANDOFF_RECORDS: Final[int] = 20


@dataclass(frozen=True, slots=True)
class AuditFilters:
    event_type: str | None = None
    actor_id: str | None = None
    session_id: str | None = None
    before_id: int | None = None
    limit: int = DEFAULT_PAGE_SIZE

    def validated(self) -> AuditFilters:
        """Clamp the page size and reject unknown event types."""
        limit = max(1, min(self.limit, MAX_PAGE_SIZE))
        event_type = self.event_type
        if event_type:
            if event_type not in {member.value for member in AuditEventType}:
                raise ValueError(f"unknown audit event type: {event_type!r}")
        else:
            event_type = None
        actor_id = (self.actor_id or "").strip()[:128] or None
        session_id = (self.session_id or "").strip()[:128] or None
        return AuditFilters(
            event_type=event_type,
            actor_id=actor_id,
            session_id=session_id,
            before_id=self.before_id if (self.before_id or 0) > 0 else None,
            limit=limit,
        )

    def query_params(self) -> dict[str, str]:
        params: dict[str, str] = {}
        if self.event_type:
            params["event_type"] = self.event_type
        if self.actor_id:
            params["actor_id"] = self.actor_id
        if self.session_id:
            params["session_id"] = self.session_id
        if self.limit != DEFAULT_PAGE_SIZE:
            params["limit"] = str(self.limit)
        return params


@dataclass(frozen=True, slots=True)
class AuditPage:
    records: list[AuditLog]
    next_before_id: int | None

    @property
    def has_more(self) -> bool:
        return self.next_before_id is not None


async def list_records(
    session: AsyncSession, filters: AuditFilters, *, tenant_id: str
) -> AuditPage:
    """Newest-first page for one tenant, with cursor pagination on ``id``."""
    applied = filters.validated()
    statement = (
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.id.desc())
        .limit(applied.limit + 1)
    )
    if applied.before_id is not None:
        statement = statement.where(AuditLog.id < applied.before_id)
    if applied.event_type is not None:
        statement = statement.where(AuditLog.event_type == AuditEventType(applied.event_type))
    if applied.actor_id is not None:
        statement = statement.where(
            AuditLog.actor_id.ilike(f"%{_escape_like(applied.actor_id)}%", escape="\\")
        )
    if applied.session_id is not None:
        statement = statement.where(AuditLog.session_id == applied.session_id)

    rows = list((await session.execute(statement)).scalars())
    has_more = len(rows) > applied.limit
    records = rows[: applied.limit]
    next_before_id = records[-1].id if has_more and records else None
    return AuditPage(records=records, next_before_id=next_before_id)


async def session_timeline(
    session: AsyncSession,
    session_id: str,
    *,
    tenant_id: str,
    limit: int = MAX_TIMELINE_RECORDS,
) -> list[AuditLog]:
    """Oldest-first timeline for the Session Inspector (bounded)."""
    if not session_id:
        return []
    bounded = max(1, min(limit, MAX_TIMELINE_RECORDS))
    statement = (
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant_id, AuditLog.session_id == session_id)
        .order_by(AuditLog.id.asc())
        .limit(bounded)
    )
    return list((await session.execute(statement)).scalars())


async def recent_security_incidents(
    session: AsyncSession,
    *,
    tenant_id: str,
    limit: int = MAX_INCIDENT_RECORDS,
) -> list[AuditLog]:
    """Newest-first ``SECURITY_INCIDENT`` rows for the dashboard panel.

    The page is the operator's first view after a leak or a quarantine, so the
    query is bounded and index-backed (``ix_audit_logs_event_type``); the full,
    filterable history remains in the audit ledger.
    """
    bounded = max(1, min(limit, MAX_INCIDENT_RECORDS))
    statement = (
        select(AuditLog)
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.event_type == AuditEventType.SECURITY_INCIDENT,
        )
        .order_by(AuditLog.id.desc())
        .limit(bounded)
    )
    return list((await session.execute(statement)).scalars())


async def recent_handoffs(
    session: AsyncSession,
    *,
    tenant_id: str,
    limit: int = MAX_HANDOFF_RECORDS,
) -> list[AuditLog]:
    """Newest-first ``HANDOFF_REQUIRED`` rows for the operator queue (ADR-022).

    A frustration verdict is a UX signal, not a security incident: it lives in
    its own event type so the incident panel stays a security surface.
    """
    bounded = max(1, min(limit, MAX_HANDOFF_RECORDS))
    statement = (
        select(AuditLog)
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.event_type == AuditEventType.HANDOFF_REQUIRED,
        )
        .order_by(AuditLog.id.desc())
        .limit(bounded)
    )
    return list((await session.execute(statement)).scalars())


async def handoff_acknowledgements(
    session: AsyncSession,
    *,
    tenant_id: str,
    conversation_ids: Sequence[str],
) -> dict[str, AuditLog]:
    """Newest ``HANDOFF_ACKNOWLEDGED`` row per conversation (ADR-022 decision 9).

    One acknowledgement per conversation is the rule, so the first row seen in
    id-descending order wins; anything older is history.
    """
    ids = [conversation_id for conversation_id in conversation_ids if conversation_id]
    if not ids:
        return {}
    statement = (
        select(AuditLog)
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.event_type == AuditEventType.HANDOFF_ACKNOWLEDGED,
            AuditLog.session_id.in_(ids),
        )
        .order_by(AuditLog.id.desc())
    )
    acknowledged: dict[str, AuditLog] = {}
    for row in (await session.execute(statement)).scalars():
        if row.session_id and row.session_id not in acknowledged:
            acknowledged[row.session_id] = row
    return acknowledged


async def handoff_transcript_ready(
    session: AsyncSession,
    *,
    tenant_id: str,
    conversation_ids: Sequence[str],
) -> set[str]:
    """Conversations whose request payload is still in ``payload_escrow``.

    The panel offers a transcript control only for these; the read itself still
    goes through the admin escrow path, so this is a hint, not an entitlement.
    """
    ids = [conversation_id for conversation_id in conversation_ids if conversation_id]
    if not ids:
        return set()
    statement = (
        select(AuditLog.session_id)
        .join(PayloadEscrow, PayloadEscrow.audit_log_id == AuditLog.id)
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.event_type == AuditEventType.INPUT_RECEIVED,
            AuditLog.session_id.in_(ids),
            PayloadEscrow.expires_at > utcnow(),
        )
        .distinct()
    )
    return {row for row in (await session.execute(statement)).scalars() if row}


async def handoff_transcript_records(
    session: AsyncSession,
    *,
    tenant_id: str,
    conversation_id: str,
) -> tuple[AuditLog | None, AuditLog | None]:
    """Newest escrowed request and delivered answer for one conversation."""
    statement = (
        select(AuditLog)
        .join(PayloadEscrow, PayloadEscrow.audit_log_id == AuditLog.id)
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.session_id == conversation_id,
            AuditLog.event_type.in_((AuditEventType.INPUT_RECEIVED, AuditEventType.RESPONSE_SENT)),
            PayloadEscrow.expires_at > utcnow(),
        )
        .order_by(AuditLog.id.desc())
    )
    request_row: AuditLog | None = None
    answer_row: AuditLog | None = None
    for row in (await session.execute(statement)).scalars():
        if row.event_type is AuditEventType.INPUT_RECEIVED and request_row is None:
            request_row = row
        elif row.event_type is AuditEventType.RESPONSE_SENT and answer_row is None:
            answer_row = row
        if request_row is not None and answer_row is not None:
            break
    return request_row, answer_row


async def handoff_record(
    session: AsyncSession,
    *,
    tenant_id: str,
    conversation_id: str,
) -> AuditLog | None:
    """The ``HANDOFF_REQUIRED`` row a caller is acting on, if this tenant has one."""
    statement = (
        select(AuditLog)
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.event_type == AuditEventType.HANDOFF_REQUIRED,
            AuditLog.session_id == conversation_id,
        )
        .order_by(AuditLog.id.desc())
        .limit(1)
    )
    return (await session.execute(statement)).scalars().first()


def next_page_url(path: str, filters: AuditFilters, next_before_id: int) -> str:
    params: dict[str, Any] = filters.query_params()
    params["before_id"] = str(next_before_id)
    return f"{path}?{urllib.parse.urlencode(params)}"


def event_type_choices() -> list[tuple[str, str]]:
    """Human labels for the audit filter, in specification order."""
    return [(member.value, member.value.replace("_", " ").title()) for member in AuditEventType]


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
