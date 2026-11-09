#!/usr/bin/env python3
"""Validate the versioned tool catalog against the live ``@tool`` registry.

ADR-009 Gate 1 requires an immutable allow-list: a tool that is registered in
code but absent from the catalog is an unapproved capability and must not ship.
This script is the CI gate for that invariant.

    uv run python scripts/validate_tool_catalog.py --check
    uv run python scripts/validate_tool_catalog.py --write   # approve the current set

``--write`` regenerates the catalog from the registry. Treat that as the review
step: the diff is the approval record. Runtime enforcement of the catalog
(filtering the model-facing tool list) is not wired yet; this check fails the
build when code and catalog disagree.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agent.tools import list_tools

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


def registered_tools() -> dict[str, dict[str, Any]]:
    """Snapshot the live registry in catalog form (sorted, JSON-safe)."""
    return {
        definition.name: {
            "description": definition.description,
            "read_only": definition.read_only,
            "required_role": definition.required_role,
            "arguments": definition.arguments_schema,
        }
        for definition in list_tools()
    }


def build_catalog(path: Path) -> dict[str, Any]:
    return {
        "version": path.stem,
        "generated_by": "scripts/validate_tool_catalog.py --write",
        "tools": registered_tools(),
    }


def load_catalog(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"catalog not found: {path} (run --write to create it)")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("tools"), dict):
        raise ValueError(f"{path} is not a catalog document with a 'tools' object")
    return payload


def compare(catalog: dict[str, Any], registered: dict[str, dict[str, Any]]) -> list[str]:
    """Return human-readable problems; an empty list means the set is in sync."""
    problems: list[str] = []
    approved = catalog["tools"]
    for name in sorted(set(registered) - set(approved)):
        problems.append(f"registered tool {name!r} is not in the catalog (unapproved)")
    for name in sorted(set(approved) - set(registered)):
        problems.append(f"catalog tool {name!r} is no longer registered (stale allow-list)")
    for name in sorted(set(approved) & set(registered)):
        expected = registered[name]
        actual = approved[name]
        for field in ("read_only", "required_role"):
            if actual.get(field) != expected[field]:
                problems.append(
                    f"{name}.{field}: catalog={actual.get(field)!r} registry={expected[field]!r}"
                )
        if actual.get("arguments") != expected["arguments"]:
            problems.append(f"{name}.arguments differs from the registry")
        if actual.get("description") != expected["description"]:
            problems.append(f"{name}.description differs from the registry")
    return problems


def main() -> int:
    args = parse_args()
    registered = registered_tools()

    if args.write:
        args.catalog.parent.mkdir(parents=True, exist_ok=True)
        payload = build_catalog(args.catalog)
        args.catalog.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )
        print(f"wrote {args.catalog} ({len(registered)} tool(s))")
        return 0

    try:
        catalog = load_catalog(args.catalog)
    except (OSError, ValueError) as exc:
        print(f"catalog error: {exc}", file=sys.stderr)
        return 1

    problems = compare(catalog, registered)
    if catalog.get("version") != args.catalog.stem:
        problems.append(
            f"catalog version {catalog.get('version')!r} does not match {args.catalog.name}"
        )

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
