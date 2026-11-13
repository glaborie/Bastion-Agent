#!/usr/bin/env python3
"""Export the audit ledger into signed, locked segments (ADR-005 decision 10).

Pages each tenant's rows into the ``compliance`` object store, one signed
segment per page, under a tenant prefix. The segment carries only the fields the
chain verifies — id, timestamp, tenant, actor, event, ``payload_hash``,
``previous_hash`` and ``record_hash`` — so exporting never re-exposes prompt or
tool text. Each object is written with ``COMPLIANCE`` object lock, so retention
is server-enforced.

    uv run python scripts/export_audit_ledger.py
    uv run python scripts/export_audit_ledger.py --tenant acme --page-size 500 --json

The store lives behind the ``compliance`` compose profile. Exit codes: ``0``
exported (or nothing to export), ``2`` the database or store could not be
reached. A failed export is not a ledger failure; verify the chain separately.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from db.export import DEFAULT_PAGE_SIZE, AuditExportError, export_ledger
from db.session import session_scope


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export the audit ledger as signed segments.")
    parser.add_argument(
        "--tenant",
        action="append",
        dest="tenants",
        metavar="ID",
        help="export only this tenant (repeatable; default: every tenant)",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        metavar="N",
        help=f"records per segment (default: {DEFAULT_PAGE_SIZE})",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    if args.page_size <= 0:
        parser.error("--page-size must be a positive integer")
    return args


async def export(tenants: list[str] | None, page_size: int) -> list[dict[str, Any]]:
    async with session_scope() as session:
        segments = await export_ledger(session, tenants=tenants, page_size=page_size)
    return [
        {
            "tenant_id": segment.manifest.tenant_id,
            "first_id": segment.manifest.first_id,
            "last_id": segment.manifest.last_id,
            "records": segment.manifest.records,
            "terminal_hash": segment.manifest.terminal_hash,
            "head_hash": segment.manifest.head_hash,
            "created_at": segment.manifest.created_at.isoformat(),
        }
        for segment in segments
    ]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        payload = asyncio.run(export(args.tenants, args.page_size))
    except AuditExportError as exc:
        print(f"could not export the audit ledger: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pylint: disable=broad-exception-caught
        print(f"could not export the audit ledger: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(payload, indent=2))
    elif not payload:
        print("OK: nothing to export")
    else:
        records = sum(segment["records"] for segment in payload)
        tenants = sorted({str(segment["tenant_id"]) for segment in payload})
        print(
            f"OK: exported {records} record(s) in {len(payload)} segment(s) "
            f"for {len(tenants)} tenant(s)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
