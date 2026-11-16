"""The one factory both demo paths use to put a ticket in the approval queue.

``scripts/seed_demo_approval.py`` and the dashboard ``seed_demo_approval``
scenario build the same row, token and ``APPROVAL_REQUESTED`` event, so a change
to the suspension contract (ADR-010 decisions 4 and 8) reaches them in one edit.
The guarded suspension in ``agent/tools/execution.py`` is deliberately not folded
in: that is the path a fingerprint or token change is tested against, and it
records the fuller audit field set.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from agent.approvals_events import publish_approval_event
from db.audit import append_audit_event
from db.models import (
    ApprovalStatus,
    AuditEventType,
    PendingApproval,
    fingerprint_request,
    hash_approval_token,
    sign_approval_token,
    utcnow,
)
from db.redis import get_redis
from db.session import session_scope
from settings import get_settings


@dataclass(frozen=True)
class DemoApproval:
    """What a caller needs back from the row it asked for."""

    ticket_id: uuid.UUID
    expires_at: datetime


async def create_demo_ticket(
    *,
    initiator_id: str,
    tenant_id: str,
    session_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    required_role: str,
) -> DemoApproval:
    """Insert a pending ticket, its audit row and its queue notification."""
    settings = get_settings()
    now = utcnow()
    expires_at = PendingApproval.expiry_for(now, settings.approval_ttl_seconds)
    ticket_id = uuid.uuid4()
    fingerprint = fingerprint_request(tool_name, arguments)
    token = sign_approval_token(
        ticket_id=ticket_id,
        request_fingerprint=fingerprint,
        expires_at=expires_at,
        secret=settings.approval_hmac_secret.get_secret_value(),
    )

    async with session_scope() as session:
        session.add(
            PendingApproval(
                ticket_id=ticket_id,
                session_id=session_id,
                tenant_id=tenant_id,
                initiator_id=initiator_id,
                tool_name=tool_name,
                tool_arguments=arguments,
                required_role=required_role,
                request_fingerprint=fingerprint,
                approval_token_hash=hash_approval_token(token),
                token_expires_at=expires_at,
                status=ApprovalStatus.PENDING,
                created_at=now,
            )
        )
        await append_audit_event(
            session,
            actor_id=initiator_id,
            tenant_id=tenant_id,
            event_type=AuditEventType.APPROVAL_REQUESTED,
            session_id=session_id,
            payload={"ticket_id": str(ticket_id), "tool": tool_name},
            metadata_json={"required_role": required_role},
        )
    await publish_approval_event(
        get_redis(settings.redis_url),
        tenant_id=tenant_id,
        event_type=AuditEventType.APPROVAL_REQUESTED,
        ticket_id=str(ticket_id),
        tool_name=tool_name,
    )
    return DemoApproval(ticket_id=ticket_id, expires_at=expires_at)
