#!/usr/bin/env python3
"""Verify the tamper-evident audit ledger.

Recomputes every record hash and every link in the SHA-256 chain, exactly as
``POST /api/audit/verify`` does, but from an operator shell:

    uv run python scripts/verify_audit_chain.py
    uv run python scripts/verify_audit_chain.py --limit 500 --json

Exit codes: ``0`` intact, ``1`` tampered, ``2`` verification could not run
(database unreachable, query error).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from db.audit import verify_audit_chain
from db.session import session_scope


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify the hash-chained audit ledger.")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="verify only the most recent N records (default: the whole ledger)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()
    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be a positive integer")
    return args


async def verify(limit: int | None) -> dict[str, Any]:
    async with session_scope() as session:
        result = await verify_audit_chain(session, limit=limit)
    return {
        "ok": result.ok,
        "checked": result.checked,
        "first_bad_id": result.first_bad_id,
        "reason": result.reason,
        "windowed": limit is not None,
    }


def main() -> int:
    args = parse_args()
    try:
        payload = asyncio.run(verify(args.limit))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        print(
            f"could not verify the audit ledger: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2

    if args.json:
        print(json.dumps(payload, indent=2))
    elif payload["ok"]:
        scope = f"the most recent {payload['checked']}" if payload["windowed"] else "all"
        print(f"OK: {scope} record(s) form an intact hash chain.")
    else:
        print(
            f"TAMPERED at id {payload['first_bad_id']}: {payload['reason']}",
            file=sys.stderr,
        )
        print(
            f"the first {payload['checked']} record(s) verified before the break",
            file=sys.stderr,
        )
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
