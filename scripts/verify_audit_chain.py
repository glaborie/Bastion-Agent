#!/usr/bin/env python3
"""Verify the tamper-evident audit ledger.

Recomputes every record hash and every link in the SHA-256 chain, exactly as
``POST /api/audit/verify`` does, but from an operator shell:

    uv run python scripts/verify_audit_chain.py
    uv run python scripts/verify_audit_chain.py --limit 500 --json
    uv run python scripts/verify_audit_chain.py --witness

``--witness`` additionally compares the live head with the newest signed witness
in object storage (ADR-005 decision 9). The chain check alone cannot see an
attacker who recomputed the whole chain inside the database; the witness can.
The store is opt-in (``--profile compliance``), so an unreachable or missing
witness is "could not verify", never a pass.

Exit codes: ``0`` intact (and, with ``--witness``, matching the witness),
``1`` tampered or divergent, ``2`` verification could not run (database or
witness store unreachable).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from db.audit import verify_audit_chain
from db.session import session_scope
from db.witness import (
    DEFAULT_SCOPE,
    AuditWitnessError,
    compare,
    latest_witness,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify the hash-chained audit ledger.")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="verify only the most recent N records (default: the whole ledger)",
    )
    parser.add_argument(
        "--witness",
        action="store_true",
        help="also compare the head with the newest witness in object storage",
    )
    parser.add_argument(
        "--scope",
        default=DEFAULT_SCOPE,
        help="witness scope to read (default: global)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()
    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be a positive integer")
    if args.witness and args.limit is not None:
        parser.error("--witness compares the whole ledger head; it cannot be combined with --limit")
    return args


async def verify(limit: int | None, *, witness_mode: bool, scope: str) -> dict[str, Any]:
    async with session_scope() as session:
        result = await verify_audit_chain(session, limit=limit)
    payload: dict[str, Any] = {
        "ok": result.ok,
        "checked": result.checked,
        "first_id": result.first_id,
        "last_id": result.last_id,
        "head_hash": result.head_hash,
        "first_bad_id": result.first_bad_id,
        "reason": result.reason,
        "windowed": limit is not None,
    }
    if not witness_mode:
        return payload

    if not result.ok:
        payload["witness"] = {"ok": False, "reason": "the ledger chain does not verify"}
        payload["ok"] = False
        return payload

    witness = await latest_witness(scope=scope)
    comparison = compare(result, witness)
    payload["witness"] = {
        "ok": comparison.ok,
        "reason": comparison.reason,
        "scope": witness.scope,
        "records": witness.records,
        "last_id": witness.last_id,
        "head_hash": witness.head_hash,
        "created_at": witness.created_at.isoformat(),
    }
    payload["ok"] = comparison.ok
    if not comparison.ok:
        payload["reason"] = comparison.reason
    return payload


def main() -> int:
    args = parse_args()
    try:
        payload = asyncio.run(verify(args.limit, witness_mode=args.witness, scope=args.scope))
    except AuditWitnessError as exc:
        print(f"could not verify the audit ledger against its witness: {exc}", file=sys.stderr)
        return 2
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
        witness = payload.get("witness")
        if witness:
            print(
                f"OK: the head matches the witness from {witness['created_at']} "
                f"({witness['records']} record(s), head {witness['head_hash']})."
            )
    else:
        if payload.get("first_bad_id") is not None:
            print(
                f"TAMPERED at id {payload['first_bad_id']}: {payload['reason']}",
                file=sys.stderr,
            )
            print(
                f"the first {payload['checked']} record(s) verified before the break",
                file=sys.stderr,
            )
        else:
            print(f"DIVERGED from the witness: {payload['reason']}", file=sys.stderr)
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
