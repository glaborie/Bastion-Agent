#!/usr/bin/env python3
"""Fail when the THREAT_MODEL.md control table drifts from the tree.

Every row of "## 4. Control status summary" is checked mechanically:

* duplicate control names fail;
* a path named in `backticks` must exist;
* a LIVE row must name a path and at least one existing ``tests/`` file;
* a PLANNED row must not name a path that already exists — the control shipped.

    uv run python scripts/check_threat_model.py --check

Exit codes: ``0`` consistent, ``1`` drift found, ``2`` the section or table is
missing or malformed.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DOCUMENT = Path(__file__).resolve().parents[1] / "THREAT_MODEL.md"
SECTION = "## 4. Control status summary"
HEADER_PREFIX = "| Control |"
STATUSES = frozenset({"LIVE", "PARTIAL", "PLANNED"})
TEST_PREFIX = "tests/"
BACKTICK = re.compile(r"`([^`]+)`")


class ThreatModelFormatError(ValueError):
    """The control section is missing or does not match the expected table."""


@dataclass(frozen=True, slots=True)
class ControlRow:
    line: int
    control: str
    status: str
    where: str


def parse_table(text: str) -> list[ControlRow]:
    """Rows of the control table, in document order."""
    section = text.find(SECTION)
    if section < 0:
        raise ThreatModelFormatError(f"missing section '{SECTION}'")
    body = text[section:]
    next_heading = body.find("\n## ", len(SECTION))
    if next_heading >= 0:
        body = body[:next_heading]

    offset = text.count("\n", 0, section)
    rows: list[ControlRow] = []
    header_seen = False
    for index, line in enumerate(body.splitlines(), start=offset + 1):
        stripped = line.strip()
        if not header_seen:
            header_seen = stripped.startswith(HEADER_PREFIX)
            continue
        if not stripped.startswith("|"):
            if rows:
                break
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) != 3:
            raise ThreatModelFormatError(f"line {index}: expected 3 columns, got {len(cells)}")
        if set(cells[0]) <= {"-", " "}:
            continue  # separator row
        rows.append(ControlRow(line=index, control=cells[0], status=cells[1], where=cells[2]))

    if not rows:
        raise ThreatModelFormatError("the control table has no rows")
    return rows


def _looks_like_path(token: str) -> bool:
    if token.startswith(("/", "ADR-")) or " " in token:
        return False
    return "/" in token or token.endswith((".py", ".json", ".yml", ".yaml", ".md", ".toml"))


def _paths(where: str) -> list[str]:
    return [token for token in BACKTICK.findall(where) if _looks_like_path(token)]


def _normalise(control: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", control.lower()).split())


def check_table(text: str, root: Path) -> list[str]:
    """Every drift between the control table and ``root``, as readable errors."""
    rows = parse_table(text)
    errors: list[str] = []
    seen: dict[str, int] = {}

    for row in rows:
        status = row.status.split("(", 1)[0].strip()
        if status not in STATUSES:
            errors.append(
                f"line {row.line}: status {row.status!r} is not one of {sorted(STATUSES)}"
            )
            continue

        name = _normalise(row.control)
        if name in seen:
            errors.append(
                f"line {row.line}: duplicate control {row.control!r} (first at line {seen[name]})"
            )
        else:
            seen[name] = row.line

        paths = _paths(row.where)
        if status == "PLANNED":
            for path in paths:
                if (root / path).exists():
                    errors.append(
                        f"line {row.line}: PLANNED control {row.control!r} names {path!r}, "
                        "which exists; mark it LIVE or drop the path"
                    )
            continue

        if status == "LIVE" and not paths:
            errors.append(f"line {row.line}: LIVE control {row.control!r} names no path")
        for path in paths:
            if not (root / path).exists():
                errors.append(f"line {row.line}: {row.control!r} names missing path {path!r}")

        if (
            status == "LIVE"
            and paths
            and not any(path.startswith(TEST_PREFIX) and (root / path).is_file() for path in paths)
        ):
            errors.append(
                f"line {row.line}: LIVE control {row.control!r} names no {TEST_PREFIX} file"
            )

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--file", default=None, help="path to THREAT_MODEL.md")
    parser.add_argument("--check", action="store_true", help="validate only (default)")
    args = parser.parse_args(argv)

    path = Path(args.file) if args.file else DEFAULT_DOCUMENT
    if not path.is_file():
        print(f"error: {path} not found", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8")
    try:
        rows = parse_table(text)
        errors = check_table(text, path.resolve().parent)
    except ThreatModelFormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"OK: {len(rows)} control rows consistent with the tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
