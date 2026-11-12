#!/usr/bin/env python3
"""Purge expired payload-escrow rows (ADR-005 decision 7).

The worker runs the same sweep every 15 minutes. This script is the on-demand
form for an operator or an incident-response step: it deletes only
``payload_escrow`` rows at or past ``expires_at`` and never touches
``audit_logs``, so the hash chain is unaffected.

    uv run python scripts/purge_payload_escrow.py --dry-run
    uv run python scripts/purge_payload_escrow.py

Exit codes: ``0`` success, ``2`` the purge could not run (database unreachable).
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import func, select

from db.escrow import purge_expired_escrow
from db.models import PayloadEscrow, utcnow
from db.session import session_scope


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Delete expired payload-escrow rows.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="count the rows that would be deleted without deleting them",
    )
    return parser.parse_args()


async def run(dry_run: bool) -> int:
    async with session_scope() as session:
        if dry_run:
            statement = (
                select(func.count())
                .select_from(PayloadEscrow)
                .where(PayloadEscrow.expires_at <= utcnow())
            )
            return int((await session.execute(statement)).scalar_one())
        return await purge_expired_escrow(session)


def main() -> int:
    args = parse_args()
    try:
        count = asyncio.run(run(args.dry_run))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        print(f"could not purge payload escrow: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    verb = "would delete" if args.dry_run else "deleted"
    print(f"{verb} {count} expired escrow row(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
