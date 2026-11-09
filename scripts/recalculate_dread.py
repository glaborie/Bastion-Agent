#!/usr/bin/env python3
"""Recompute the DREAD table and risk-priority list in ``THREAT_MODEL.md``.

DREAD is five 1-10 factors per threat; the total is their sum. This script
recomputes every total from the factors and rebuilds the "Risk Priority" list
(highest first, ties in table order), so a hand-edited factor cannot leave a
stale total behind.

    uv run python scripts/recalculate_dread.py --check    # CI gate, no writes
    uv run python scripts/recalculate_dread.py --write    # apply the fix

Exit codes: ``0`` consistent (or written), ``1`` drift found in ``--check`` or
the document is malformed.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DOCUMENT = Path("THREAT_MODEL.md")
SECTION = "### DREAD Scoring"
HEADER_PREFIX = "| Threat | Damage Potential"
PRIORITY_HEADING = "**Risk Priority:**"
FACTOR_COUNT = 5
ROW_COLUMNS = FACTOR_COUNT + 2


class DreadFormatError(ValueError):
    """The DREAD section is missing or does not match the expected table."""


@dataclass(frozen=True, slots=True)
class DreadRow:
    line_index: int
    label: str
    factors: tuple[int, ...]
    stored_total: int

    @property
    def total(self) -> int:
        return sum(self.factors)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Recompute DREAD totals in the threat model.")
    parser.add_argument(
        "--document",
        type=Path,
        default=DEFAULT_DOCUMENT,
        help=f"threat-model document (default: {DEFAULT_DOCUMENT})",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="fail on drift (default)")
    mode.add_argument("--write", action="store_true", help="rewrite the document in place")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser.parse_args()


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _as_int(raw: str, label: str, field: str) -> int:
    try:
        return int(raw.strip("* "))
    except ValueError as exc:
        raise DreadFormatError(f"row {label!r}: {field} is not an integer: {raw!r}") from exc


def _as_factor(raw: str, label: str, position: int) -> int:
    value = _as_int(raw, label, f"factor {position}")
    if not 1 <= value <= 10:
        raise DreadFormatError(f"row {label!r}: factor {position} must be 1-10, got {value}")
    return value


def analyse(text: str) -> tuple[list[DreadRow], int, int, list[str]]:
    """Return rows, the priority-list span, and the raw lines."""
    lines = text.splitlines()
    try:
        section = next(i for i, line in enumerate(lines) if line.strip() == SECTION)
    except StopIteration as exc:
        raise DreadFormatError(f"section {SECTION!r} not found") from exc

    try:
        header = next(i for i in range(section, len(lines)) if lines[i].startswith(HEADER_PREFIX))
    except StopIteration as exc:
        raise DreadFormatError("DREAD table header not found") from exc

    rows: list[DreadRow] = []
    index = header + 2  # skip the markdown separator row
    while index < len(lines) and lines[index].startswith("|"):
        cells = _cells(lines[index])
        if len(cells) != ROW_COLUMNS:
            raise DreadFormatError(
                f"line {index + 1}: expected {ROW_COLUMNS} columns, got {len(cells)}"
            )
        label = cells[0].strip("* ").strip()
        if not label:
            raise DreadFormatError(f"line {index + 1}: empty threat name")
        factors = tuple(
            _as_factor(cells[position], label, position - 1)
            for position in range(1, FACTOR_COUNT + 1)
        )
        stored = _as_int(cells[-1], label, "total score")
        rows.append(DreadRow(index, label, factors, stored))
        index += 1

    if not rows:
        raise DreadFormatError("the DREAD table has no rows")
    labels = [row.label for row in rows]
    if len(set(labels)) != len(labels):
        raise DreadFormatError("the DREAD table contains duplicate threat names")

    try:
        heading = next(i for i in range(index, len(lines)) if lines[i].strip() == PRIORITY_HEADING)
    except StopIteration as exc:
        raise DreadFormatError(f"{PRIORITY_HEADING!r} not found after the table") from exc

    start = heading + 1
    while start < len(lines) and not lines[start].strip():
        start += 1
    end = start
    while end < len(lines) and lines[end].strip()[:1].isdigit() and ". " in lines[end]:
        end += 1
    return rows, start, end, lines


def render(text: str) -> tuple[str, list[str]]:
    """Return the corrected document and a list of human-readable changes."""
    rows, priority_start, priority_end, lines = analyse(text)
    changes: list[str] = []

    for row in rows:
        if row.stored_total == row.total:
            continue
        cells = _cells(lines[row.line_index])
        cells[-1] = f"**{row.total}**"
        lines[row.line_index] = "| " + " | ".join(cells) + " |"
        changes.append(f"{row.label}: {row.stored_total} -> {row.total}")

    ordered = sorted(enumerate(rows), key=lambda item: (-item[1].total, item[0]))
    priority = [
        f"{rank}. {row.label} — {row.total}" for rank, (_, row) in enumerate(ordered, start=1)
    ]
    if lines[priority_start:priority_end] != priority:
        lines[priority_start:priority_end] = priority
        changes.append("risk-priority list refreshed")

    rendered = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    return rendered, changes


def main() -> int:
    args = parse_args()
    try:
        original = args.document.read_text(encoding="utf-8")
        rendered, changes = render(original)
    except (OSError, DreadFormatError) as exc:
        print(f"cannot parse {args.document}: {exc}", file=sys.stderr)
        return 1

    if args.write:
        if changes:
            args.document.write_text(rendered, encoding="utf-8")
        if args.json:
            print(json.dumps({"written": bool(changes), "changes": changes}, indent=2))
        elif changes:
            print(f"updated {args.document}")
            for change in changes:
                print(f"  - {change}")
        else:
            print(f"OK: {args.document} is already consistent")
        return 0

    drifted = rendered != original
    if args.json:
        print(json.dumps({"ok": not drifted, "changes": changes}, indent=2))
    elif drifted:
        print(f"DRIFT: {args.document} needs {len(changes)} change(s)", file=sys.stderr)
        for change in changes:
            print(f"  - {change}", file=sys.stderr)
        print("Run --write to apply them.", file=sys.stderr)
    else:
        print(f"OK: DREAD totals and priority order in {args.document} are consistent")
    return 1 if drifted else 0


if __name__ == "__main__":
    raise SystemExit(main())
