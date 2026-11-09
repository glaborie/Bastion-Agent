#!/usr/bin/env python3
"""Validate the ADR set in docs/adr against the project's conventions.

Checks every ADR file for the required structure and metadata, cross-checks the
index, and rejects machine-local paths. Exit code 1 on any violation.

    uv run python scripts/check_adrs.py
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ADR_DIR = ROOT / "docs" / "adr"
INDEX = ADR_DIR / "ADR-Index.md"

STATUSES = {"Proposed", "Accepted", "Superseded", "Deprecated"}
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
FILENAME = re.compile(r"^ADR-(\d{3})\.md$")
INDEX_ROW = re.compile(r"^\|\s*(\d{3})\s*\|\s*([^|]+?)\s*\|\s*([A-Za-z]+)\s*\|\s*$", re.M)

LOCAL_PATH_PATTERNS = (
    re.compile(r"/home/[A-Za-z0-9._-]+"),
    re.compile(r"~/\.(?:hermes|opencode|config|local)\b"),
    re.compile(r"[A-Za-z]:\\\\Users"),
)


def check_adr(path: pathlib.Path) -> list[str]:
    number = FILENAME.match(path.name)
    assert number is not None
    expected = number.group(1)
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []

    first_line = text.splitlines()[0] if text else ""
    if not re.match(rf"^# ADR-{expected}: \S", first_line):
        errors.append(f"title must be '# ADR-{expected}: <Title>'")

    fields: dict[str, str] = {}
    for field in ("Status", "Date", "Last modified"):
        match = re.search(rf"^\*\*{field}:\*\*\s*(.+?)\s*$", text, re.M)
        if not match:
            errors.append(f"missing '**{field}:**'")
        else:
            fields[field] = match.group(1)
    if "Status" in fields and fields["Status"] not in STATUSES:
        errors.append(f"invalid status {fields['Status']!r}; expected one of {sorted(STATUSES)}")
    for field in ("Date", "Last modified"):
        if field in fields and not DATE.match(fields[field]):
            errors.append(f"**{field}:** must be YYYY-MM-DD, got {fields[field]!r}")

    for section in ("## Context", "## Decision", "## Consequences"):
        if section not in text:
            errors.append(f"missing {section}")

    if "**Pros**" not in text:
        errors.append("missing **Pros** bullet")
    if "**Cons**" not in text:
        errors.append("missing **Cons** bullet")

    if "## Context" in text and "## Decision" in text:
        context = text.split("## Context", 1)[1].split("## Decision", 1)[0].strip()
        paragraphs = [p for p in context.split("\n\n") if p.strip()]
        if len(paragraphs) < 2:
            errors.append("## Context needs at least two paragraphs")

    if "## Decision" in text and "## Consequences" in text:
        decision = text.split("## Decision", 1)[1].split("## Consequences", 1)[0]
        if not re.search(r"^\s*1\.\s+", decision, re.M):
            errors.append("## Decision must be a numbered list starting at 1.")

    for pattern in LOCAL_PATH_PATTERNS:
        if match := pattern.search(text):
            errors.append(f"machine-local path found: {match.group(0)}")

    return errors


def main() -> int:
    if not ADR_DIR.is_dir():
        print(f"missing directory: {ADR_DIR}")
        return 1

    files = sorted(p for p in ADR_DIR.iterdir() if FILENAME.match(p.name))
    failures: dict[str, list[str]] = {}

    numbers = [FILENAME.match(p.name).group(1) for p in files]  # type: ignore[union-attr]
    if numbers != [f"{i:03d}" for i in range(1, len(numbers) + 1)]:
        failures["numbering"] = [
            f"expected continuous ADR-001..ADR-{len(numbers):03d}, found {numbers}"
        ]

    for path in files:
        if errors := check_adr(path):
            failures[str(path.relative_to(ROOT))] = errors

    if not INDEX.is_file():
        failures["docs/adr/ADR-Index.md"] = ["index file is missing"]
    else:
        index_text = INDEX.read_text(encoding="utf-8")
        rows = INDEX_ROW.findall(index_text)
        indexed = {number for number, _title, _status in rows}
        missing = sorted(set(numbers) - indexed)
        extra = sorted(indexed - set(numbers))
        if missing:
            failures.setdefault("docs/adr/ADR-Index.md", []).append(
                f"ADR(s) not in index: {missing}"
            )
        if extra:
            failures.setdefault("docs/adr/ADR-Index.md", []).append(
                f"index row(s) without a file: {extra}"
            )
        for number, title, status in rows:
            if status not in STATUSES:
                failures.setdefault("docs/adr/ADR-Index.md", []).append(
                    f"row {number} has invalid status {status!r}"
                )
            if not title.strip():
                failures.setdefault("docs/adr/ADR-Index.md", []).append(
                    f"row {number} has an empty title"
                )

    if failures:
        for target, errors in failures.items():
            print(f"FAIL {target}")
            for error in errors:
                print(f"     - {error}")
        print(f"\n{len(files)} ADR(s) checked; {len(failures)} problem(s).")
        return 1

    print(f"OK: {len(files)} ADRs, index consistent, no machine-local paths.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
