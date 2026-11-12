#!/usr/bin/env python3
"""Originate a guarded tool call for a live demo.

There is no chat endpoint yet, so this script plays the agent's role: it
enqueues ``execute_tool_job`` on the ARQ queue on behalf of a specific Keycloak
subject. Read-only tools return immediately; mutating tools suspend and print a
ticket id, which a second operator approves in the dashboard.

    uv run python scripts/demo_tool_request.py \
        --tool execute_file_write \
        --actor-sub "$ALICE_SUB" \
        --role operator \
        --arg path=reports/q1.txt \
        --arg content='Q1 revenue'

``--actor-sub`` must be the OIDC ``sub`` claim (``GET /auth/me`` -> ``subject``),
never a username: four-eyes compares it with the approver's subject.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
from typing import Any

from arq import create_pool
from arq.connections import RedisSettings

from agent.job_auth import TOOL_JOB, sign_job, tool_job_fields
from settings import get_settings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tool", required=True, help="registered tool name")
    parser.add_argument("--actor-sub", required=True, help="initiator OIDC subject (JWT sub)")
    parser.add_argument(
        "--tenant-id",
        default="default",
        help="tenant scope of the initiator (default: default)",
    )
    parser.add_argument(
        "--role",
        action="append",
        default=[],
        help="role held by the actor (repeatable), e.g. --role operator",
    )
    parser.add_argument(
        "--arg",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="tool argument (repeatable); JSON values are parsed, otherwise strings",
    )
    parser.add_argument(
        "--session-id",
        default=None,
        help="audit session id (default: a fresh demo-<hex> id)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="seconds to wait for the worker result",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print only the JSON result (no hints)",
    )
    return parser.parse_args()


def _coerce(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return raw


def _arguments(items: list[str]) -> dict[str, Any]:
    arguments: dict[str, Any] = {}
    for item in items:
        key, separator, value = item.partition("=")
        if not separator or not key:
            raise SystemExit(f"invalid --arg {item!r}; expected KEY=VALUE")
        arguments[key] = _coerce(value)
    return arguments


async def run(args: argparse.Namespace) -> int:
    settings = get_settings()
    session_id = args.session_id or f"demo-{uuid.uuid4().hex[:8]}"
    fields = tool_job_fields(
        tool_name=args.tool,
        actor_id=args.actor_sub,
        tenant_id=args.tenant_id,
        session_id=session_id,
        roles=list(args.role),
        arguments=_arguments(args.arg),
    )
    envelope = sign_job(
        TOOL_JOB,
        fields,
        secret=settings.job_signing_secret.get_secret_value(),
        ttl_seconds=settings.job_signature_ttl_seconds,
    )
    pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    try:
        job = await pool.enqueue_job(
            "execute_tool_job",
            **fields,
            **envelope,
            _queue_name=settings.arq_queue_name,
        )
        if job is None:  # pragma: no cover - defensive
            print("the job could not be queued")
            return 1
        try:
            result = await job.result(timeout=args.timeout)
        except TimeoutError:
            print(
                "no result before the timeout; is the worker running "
                "(docker compose ps worker) and on the same ARQ queue?"
            )
            return 1
    finally:
        await pool.aclose()

    print(json.dumps(result, indent=2, default=str))
    if args.json:
        return 0 if result.get("status") in {"executed", "approval_pending"} else 1

    status = result.get("status")
    print()
    if status == "approval_pending":
        print(f"ticket     : {result.get('ticket_id')}")
        print(f"expires at : {result.get('expires_at')}")
        print(f"session    : {session_id}")
        print("Approve it in http://localhost:8000/dashboard as another operator.")
    elif status == "executed":
        print(f"session    : {session_id}")
        print("Read-only tool executed without a ticket.")
    else:
        print(f"tool call did not proceed ({status}); see the error above.")
        return 1
    return 0


def main() -> int:
    return asyncio.run(run(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
