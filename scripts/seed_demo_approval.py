#!/usr/bin/env python3
"""Create a suspended write-tool ticket without running a worker.

For the full flow use ``scripts/demo_tool_request.py``, which enqueues the real
``execute_tool_job`` and lets the worker execute the approved ticket. This
script remains useful for populating the approval queue when no worker is
running; it writes the same ``PendingApproval`` row and ``APPROVAL_REQUESTED``
audit record the worker produces.

    uv run python scripts/seed_demo_approval.py --initiator-id <alice-sub>

The initiator id must be the Keycloak ``sub`` of the user who should not be able
to approve the ticket (fetch it from ``GET /auth/me``).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
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
from db.session import init_models, session_scope
from settings import get_settings


async def create_ticket(
    *,
    initiator_id: str,
    tenant_id: str,
    session_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    required_role: str,
) -> uuid.UUID:
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
    return ticket_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--initiator-id",
        required=True,
        help="Keycloak sub of the initiator (cannot approve their own ticket)",
    )
    parser.add_argument("--session-id", default=None, help="Session id to attach the ticket to")
    parser.add_argument(
        "--tenant-id",
        default="default",
        help="Tenant id for the ticket and its audit row (ADR-015)",
    )
    parser.add_argument("--tool", default="execute_file_write", help="Tool name")
    parser.add_argument("--path", default="reports/q3.csv", help="Tool path argument")
    parser.add_argument("--content", default="quarterly revenue", help="Tool content argument")
    parser.add_argument("--required-role", default="operator", help="Role required to decide")
    args = parser.parse_args()

    async def run() -> None:
        await init_models()
        ticket_id = await create_ticket(
            initiator_id=args.initiator_id,
            tenant_id=args.tenant_id,
            session_id=args.session_id or f"demo-{uuid.uuid4()}",
            tool_name=args.tool,
            arguments={"path": args.path, "content": args.content},
            required_role=args.required_role,
        )
        print(json.dumps({"ticket_id": str(ticket_id), "status": "pending"}, indent=2))

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
