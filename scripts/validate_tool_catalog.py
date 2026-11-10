#!/usr/bin/env python3
"""Validate the versioned tool catalog against the live ``@tool`` registry.

ADR-009 Gate 1 requires an immutable allow-list: a tool that is registered in
code but absent from the catalog is an unapproved capability and must not ship.
This script is the CI gate for that invariant; the gateway and the ARQ worker
run :func:`agent.tools.catalog.verify_registry` at startup, so the same drift
also stops a deployment.

    uv run python scripts/validate_tool_catalog.py --check
    uv run python scripts/validate_tool_catalog.py --write   # approve the current set

``--write`` regenerates the catalog from the registry. Treat that as the review
step: the diff is the approval record. A read-only tool that the current catalog
marks ``require_approval`` keeps that flag, so regeneration cannot silently
loosen four-eyes.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agent.tools import list_tools
from agent.tools.catalog import compare_catalog, load_catalog
from agent.tools.decorator import ToolCatalogError

DEFAULT_CATALOG = Path("docs/tools/v1.json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the tool catalog allow-list.")
    parser.add_argument(
        "--catalog",
        type=Path,
        default=DEFAULT_CATALOG,
        help=f"catalog file (default: {DEFAULT_CATALOG})",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="fail on drift (default)",
    )
    mode.add_argument(
        "--write",
        action="store_true",
        help="regenerate the catalog from the live registry",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser.parse_args()


def preserved_approvals(path: Path) -> dict[str, bool]:
    """``require_approval`` flags from the current catalog, when it parses."""
    if not path.is_file():
        return {}
    try:
        catalog = load_catalog(path)
    except ToolCatalogError:
        return {}
    return {name: entry.require_approval for name, entry in catalog.tools.items()}


def registered_tools(path: Path) -> dict[str, dict[str, Any]]:
    """Snapshot the live registry in catalog form (sorted, JSON-safe)."""
    forced = preserved_approvals(path)
    return {
        definition.name: {
            "description": definition.description,
            "read_only": definition.read_only,
            "required_role": definition.required_role,
            "require_approval": (
                True if not definition.read_only else forced.get(definition.name, False)
            ),
            "arguments": definition.arguments_schema,
        }
        for definition in list_tools()
    }


def build_catalog(path: Path) -> dict[str, Any]:
    return {
        "version": path.stem,
        "generated_by": "scripts/validate_tool_catalog.py --write",
        "tools": registered_tools(path),
    }


def main() -> int:
    args = parse_args()

    if args.write:
        args.catalog.parent.mkdir(parents=True, exist_ok=True)
        payload = build_catalog(args.catalog)
        args.catalog.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )
        print(f"wrote {args.catalog} ({len(payload['tools'])} tool(s))")
        return 0

    registered = registered_tools(args.catalog)
    try:
        catalog = load_catalog(args.catalog)
    except ToolCatalogError as exc:
        print(f"catalog error: {exc}", file=sys.stderr)
        return 1

    problems = compare_catalog(catalog, list_tools())
    if catalog.version != args.catalog.stem:
        problems.append(f"catalog version {catalog.version!r} does not match {args.catalog.name}")

    if args.json:
        print(
            json.dumps(
                {
                    "ok": not problems,
                    "catalog": str(args.catalog),
                    "registered": sorted(registered),
                    "problems": problems,
                },
                indent=2,
            )
        )
    elif problems:
        print(f"DRIFT: {len(problems)} problem(s) in {args.catalog}", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nRun --write to approve the current registry, then review the diff.", file=sys.stderr
        )
    else:
        print(f"OK: {len(registered)} tool(s) match {args.catalog}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
