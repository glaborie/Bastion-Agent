#!/usr/bin/env python3
"""Publish a signed witness of the audit chain head (ADR-005 decision 9).

The witness is one small object in a versioned bucket under ``COMPLIANCE``
object lock: scope, id range, row count, terminal ``record_hash``, timestamp and
an HMAC. It carries no payloads, so publishing it leaks nothing the ledger has
not already reduced to a hash.

    uv run python scripts/write_audit_witness.py
    uv run python scripts/write_audit_witness.py --scope global --json

The store lives behind the ``compliance`` compose profile. Running without it is
not a failure of the ledger, so the exit code distinguishes the cases: ``0``
published, ``1`` the ledger chain does not verify, ``2`` the store or database
could not be reached.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from db.audit import verify_audit_chain
from db.session import session_scope
from db.witness import DEFAULT_SCOPE, AuditWitnessError, publish_witness


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Publish a signed witness of the audit chain head."
    )
    parser.add_argument("--scope", default=DEFAULT_SCOPE, help="witness scope (default: global)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser.parse_args(argv)


async def publish(scope: str) -> dict[str, Any]:
    async with session_scope() as session:
        result = await verify_audit_chain(session)
    if not result.ok:
        return {
            "published": False,
            "reason": result.reason,
            "first_bad_id": result.first_bad_id,
            "checked": result.checked,
        }
    witness = await publish_witness(result, scope=scope)
    return {
        "published": True,
        "scope": witness.scope,
        "first_id": witness.first_id,
        "last_id": witness.last_id,
        "records": witness.records,
        "head_hash": witness.head_hash,
        "created_at": witness.created_at.isoformat(),
        "signature": witness.signature,
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        payload = asyncio.run(publish(args.scope))
    except AuditWitnessError as exc:
        print(f"could not write the audit witness: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pylint: disable=broad-exception-caught
        print(f"could not write the audit witness: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(payload, indent=2))
    elif not payload["published"]:
        print(
            f"REFUSED: the ledger chain does not verify at id {payload['first_bad_id']}: "
            f"{payload['reason']}",
            file=sys.stderr,
        )
    else:
        print(
            f"OK: witnessed {payload['records']} record(s) "
            f"(ids {payload['first_id']}..{payload['last_id']}), "
            f"head {payload['head_hash']}"
        )
    return 0 if payload["published"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
