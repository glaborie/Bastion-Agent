#!/usr/bin/env python3
"""Create a suspended write-tool ticket without running a worker.

For the full flow use ``scripts/demo_tool_request.py``, which enqueues the real
``execute_tool_job`` and lets the worker execute the approved ticket. This
script remains useful for populating the approval queue when no worker is
running; it writes the same pending-approval row and ``APPROVAL_REQUESTED``
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

from agent.demo.tickets import create_demo_ticket
from db.session import init_models


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
        ticket = await create_demo_ticket(
            initiator_id=args.initiator_id,
            tenant_id=args.tenant_id,
            session_id=args.session_id or f"demo-{uuid.uuid4()}",
            tool_name=args.tool,
            arguments={"path": args.path, "content": args.content},
            required_role=args.required_role,
        )
        print(json.dumps({"ticket_id": str(ticket.ticket_id), "status": "pending"}, indent=2))

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
