#!/usr/bin/env python3
"""Validate and render BACKLOG.md for Bastion-Agent.

The backlog is a single append-only Markdown file. This script is the only
writer of its generated sections, so the board and the index can never drift
from the items themselves. It deliberately mirrors scripts/check_adrs.py:
deterministic, offline, no third-party dependencies, non-zero exit on error.

Usage:
    uv run python scripts/check_backlog.py             # validate (default)
    uv run python scripts/check_backlog.py --write     # validate, then refresh Board + Index
    uv run python scripts/check_backlog.py --next      # items that are ready to start
    uv run python scripts/check_backlog.py --next --json

Exit codes:
    0  valid (warnings allowed)
    1  validation errors
    2  BACKLOG.md missing, unreadable or missing its generated-section markers
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

STATUSES = ("inbox", "ready", "active", "blocked", "done", "dropped")
PRIORITIES = ("P0", "P1", "P2", "P3")
AREAS = ("agent", "gateway", "db", "infra", "security", "evals", "docs", "tooling")
PHASES = ("v0.1", "v0.2", "v0.3", "v0.4", "v0.5", "v0.6")
DONE_STATES = {"done", "dropped"}

REQUIRED_FIELDS = (
    "status",
    "priority",
    "phase",
    "area",
    "tags",
    "depends-on",
    "spec",
    "created",
    "updated",
    "source",
)
REQUIRED_SECTIONS = ("Problem", "Outcome")
INBOX_MAX_AGE_DAYS = 14
MAX_TAGS = 6
MAX_FUZZY_RATIO = 0.90

SECTION_RE = re.compile("[*][*](Problem|Outcome)[.]?[*][*]", re.MULTILINE)
HEADING_RE = re.compile(r"^### (IDEA-\d{3}): (.+)$", re.MULTILINE)
FIELD_RE = re.compile(r"^- ([a-z][a-z-]*): (.*)$")
META_RE = re.compile(r"^- (current-phase|wip-limit|next-id): (\S+)$", re.MULTILINE)
ACCEPTANCE_RE = re.compile(r"^\*\*Acceptance\*\*(.*?)(?=^\*\*|\Z)", re.MULTILINE | re.DOTALL)
CHECKBOX_RE = re.compile(r"^- \[([ xX])\]", re.MULTILINE)
TAG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SPEC_RE = re.compile(r"^(?:ADR-\d{3}|ADR-Index|HANDOVER_SPEC|-)$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

BOARD_BEGIN = "<!-- BEGIN BOARD -->"
BOARD_END = "<!-- END BOARD -->"
INDEX_BEGIN = "<!-- BEGIN INDEX -->"
INDEX_END = "<!-- END INDEX -->"
NO_DEPS = {"", "-", "--", "none"}


@dataclass
class Item:
    id: str
    title: str
    line: int
    body: str
    fields: dict[str, str] = field(default_factory=dict)
    acceptance: list[bool] = field(default_factory=list)

    @property
    def status(self) -> str:
        return self.fields.get("status", "")

    @property
    def priority(self) -> str:
        return self.fields.get("priority", "?")

    @property
    def phase(self) -> str:
        return self.fields.get("phase", "?")

    @property
    def deps(self) -> list[str]:
        raw = self.fields.get("depends-on", "")
        if raw.strip().lower() in NO_DEPS:
            return []
        return [part.strip() for part in raw.split(",") if part.strip()]


def parse(text: str) -> tuple[dict[str, str], list[Item]]:
    meta: dict[str, str] = {}
    for match in META_RE.finditer(text):
        meta.setdefault(match.group(1), match.group(2).strip())

    headings = list(HEADING_RE.finditer(text))
    items: list[Item] = []
    for index, match in enumerate(headings):
        start = match.end()
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        body = text[start:end]

        fields: dict[str, str] = {}
        lines = body.splitlines()
        cursor = 0
        while cursor < len(lines) and not lines[cursor].strip():
            cursor += 1
        while cursor < len(lines):
            field_match = FIELD_RE.match(lines[cursor])
            if not field_match:
                break
            fields[field_match.group(1)] = field_match.group(2).strip()
            cursor += 1

        acceptance: list[bool] = []
        acceptance_match = ACCEPTANCE_RE.search(body)
        if acceptance_match:
            acceptance = [
                box.strip().lower() == "x" for box in CHECKBOX_RE.findall(acceptance_match.group(1))
            ]

        items.append(
            Item(
                id=match.group(1),
                title=match.group(2).strip(),
                line=text.count("\n", 0, match.start()) + 1,
                body=body,
                fields=fields,
                acceptance=acceptance,
            )
        )
    return meta, items


def find_cycle(graph: dict[str, list[str]]) -> list[str] | None:
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        status = state.get(node, 0)
        if status == 1:
            return [*stack[stack.index(node) :], node]
        if status == 2:
            return None
        state[node] = 1
        stack.append(node)
        for dep in graph.get(node, []):
            if dep in graph:
                cycle = visit(dep)
                if cycle:
                    return cycle
        stack.pop()
        state[node] = 2
        return None

    for node in graph:
        cycle = visit(node)
        if cycle:
            return cycle
    return None


def normalize_title(title: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9 ]+", " ", title.lower()).split())


def validate(text: str) -> tuple[dict[str, str], list[Item], list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    meta, items = parse(text)

    for key in ("current-phase", "wip-limit", "next-id"):
        if key not in meta:
            errors.append(f"meta: missing '- {key}: ...' line under the header")
    current_phase = meta.get("current-phase", "")
    if current_phase and current_phase not in PHASES:
        errors.append(f"meta: current-phase '{current_phase}' is not one of {', '.join(PHASES)}")
    try:
        wip_limit = int(meta.get("wip-limit", "3"))
        if wip_limit < 1:
            raise ValueError
    except ValueError:
        errors.append("meta: wip-limit must be a positive integer")
        wip_limit = 3

    if not items:
        errors.append("no items: expected at least one '### IDEA-NNN: Title' heading")

    seen_ids: set[str] = set()
    for item in items:
        where = f"{item.id} (line {item.line})"
        if item.id in seen_ids:
            errors.append(f"{where}: duplicate id")
        seen_ids.add(item.id)

        for key in REQUIRED_FIELDS:
            if key not in item.fields:
                errors.append(f"{where}: missing field '{key}'")
        present = {match.group(1) for match in SECTION_RE.finditer(item.body)}
        for section in REQUIRED_SECTIONS:
            if section not in present:
                errors.append(f"{where}: missing '{section}' section")

        if item.status and item.status not in STATUSES:
            errors.append(f"{where}: status '{item.status}' is not one of {', '.join(STATUSES)}")
        if item.priority and item.priority not in PRIORITIES:
            errors.append(
                f"{where}: priority '{item.priority}' is not one of {', '.join(PRIORITIES)}"
            )
        if item.phase and item.phase not in PHASES:
            errors.append(f"{where}: phase '{item.phase}' is not one of {', '.join(PHASES)}")
        area = item.fields.get("area", "")
        if area and area not in AREAS:
            errors.append(f"{where}: area '{area}' is not one of {', '.join(AREAS)}")

        tags_raw = item.fields.get("tags", "")
        if tags_raw and tags_raw != "-":
            tags = [tag.strip() for tag in tags_raw.split(",") if tag.strip()]
            if not tags:
                errors.append(f"{where}: tags must be a comma-separated list or '-'")
            if len(tags) > MAX_TAGS:
                errors.append(f"{where}: {len(tags)} tags (maximum {MAX_TAGS})")
            for tag in tags:
                if not TAG_RE.match(tag):
                    errors.append(f"{where}: tag '{tag}' must be lowercase kebab-case")
            if len(set(tags)) != len(tags):
                errors.append(f"{where}: duplicate tag")

        spec = item.fields.get("spec", "")
        if spec and not SPEC_RE.match(spec):
            errors.append(
                f"{where}: spec '{spec}' must be ADR-NNN, ADR-Index, HANDOVER_SPEC or '-'"
            )

        created_raw = item.fields.get("created", "")
        updated_raw = item.fields.get("updated", "")
        created = updated = None
        for label, value in (("created", created_raw), ("updated", updated_raw)):
            if not value:
                continue
            if not DATE_RE.match(value):
                errors.append(f"{where}: {label} '{value}' must be YYYY-MM-DD")
                continue
            try:
                parsed = date.fromisoformat(value)
            except ValueError:
                errors.append(f"{where}: {label} '{value}' is not a real date")
                continue
            if label == "created":
                created = parsed
            else:
                updated = parsed
        if created and updated and updated < created:
            errors.append(f"{where}: updated {updated_raw} is before created {created_raw}")

        for dep in item.deps:
            if not re.match(r"^IDEA-\d{3}$", dep):
                errors.append(f"{where}: depends-on '{dep}' must be IDEA-NNN")
            elif dep == item.id:
                errors.append(f"{where}: depends on itself")
            elif dep not in seen_ids and dep not in {other.id for other in items}:
                errors.append(f"{where}: depends-on '{dep}' does not exist")

        if item.status in ("ready", "active"):
            unresolved = [
                dep
                for dep in item.deps
                if next((other.status for other in items if other.id == dep), "missing")
                not in DONE_STATES
            ]
            if unresolved:
                errors.append(
                    f"{where}: status '{item.status}' but blocked by {', '.join(unresolved)}"
                )
            if current_phase and item.phase > current_phase:
                warnings.append(
                    f"{where}: {item.phase} work marked '{item.status}' while current phase is "
                    f"{current_phase}"
                )

        if item.status == "blocked" and not item.fields.get("blocked-by"):
            errors.append(f"{where}: status 'blocked' requires a 'blocked-by' field")

        if item.status == "done":
            if not item.acceptance:
                errors.append(f"{where}: status 'done' needs an **Acceptance** checklist")
            unchecked = sum(1 for checked in item.acceptance if not checked)
            if unchecked:
                errors.append(
                    f"{where}: status 'done' with {unchecked} unchecked acceptance box(es)"
                )

        if item.status == "inbox" and created:
            age = (date.today() - created).days
            if age > INBOX_MAX_AGE_DAYS:
                warnings.append(f"{where}: untriaged inbox item is {age} days old")

    ids = {item.id for item in items}
    graph = {item.id: [dep for dep in item.deps if dep in ids] for item in items}
    cycle = find_cycle(graph)
    if cycle:
        errors.append(f"dependency cycle: {' -> '.join(cycle)}")

    titles: dict[str, str] = {}
    for item in items:
        normalized = normalize_title(item.title)
        if normalized in titles:
            errors.append(f"{item.id}: duplicate title of {titles[normalized]}")
            continue
        titles[normalized] = item.id

    for index, item in enumerate(items):
        for other in items[index + 1 :]:
            if normalize_title(item.title) == normalize_title(other.title):
                continue
            ratio = difflib.SequenceMatcher(
                None, normalize_title(item.title), normalize_title(other.title)
            ).ratio()
            if ratio >= MAX_FUZZY_RATIO:
                warnings.append(
                    f"{item.id}: title is {ratio:.0%} similar to {other.id}; check for duplicates"
                )

    numeric = sorted(int(item.id.split("-")[1]) for item in items)
    if numeric:
        expected = f"IDEA-{numeric[-1] + 1:03d}"
        if meta.get("next-id") and meta["next-id"] != expected:
            warnings.append(f"meta: next-id is {meta['next-id']}, expected {expected}")
        gaps = [
            f"IDEA-{number:03d}"
            for number in range(numeric[0], numeric[-1])
            if number not in numeric
        ]
        if gaps:
            warnings.append(f"meta: id gap at {', '.join(gaps)} (dropped ids keep their number)")

    active = [item for item in items if item.status == "active"]
    if len(active) > wip_limit:
        warnings.append(
            f"{len(active)} items are 'active' but wip-limit is {wip_limit}: "
            f"{', '.join(item.id for item in active)}"
        )

    return meta, items, errors, warnings


def render_board(meta: dict[str, str], items: list[Item]) -> str:
    lines: list[str] = []
    for status in STATUSES:
        group = [item for item in items if item.status == status]
        if status in ("dropped",) and not group:
            continue
        lines.append(f"### {status.capitalize()} ({len(group)})")
        lines.append("")
        if not group:
            lines.append("_none_")
        else:
            for item in group:
                suffix = ""
                if item.deps:
                    suffix = f" (waiting on {', '.join(item.deps)})"
                lines.append(
                    f"- `{item.id}` {item.priority} {item.phase} {item.fields.get('area', '?')}"
                    f" - {item.title}{suffix}"
                )
        lines.append("")
    phase = meta.get("current-phase", "?")
    lines.append(
        f"_Phase gate: {phase} - items at or below it may start; later phases stay parked._"
    )
    return "\n".join(lines).rstrip() + "\n"


def render_index(items: list[Item]) -> str:
    lines = [
        "| ID | Status | Prio | Phase | Area | Title |",
        "|---|---|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            f"| {item.id} | {item.status or '?'} | {item.priority} | {item.phase} "
            f"| {item.fields.get('area', '?')} | {item.title} |"
        )
    return "\n".join(lines) + "\n"


def replace_between(text: str, begin: str, end: str, body: str) -> str:
    start = text.find(begin)
    stop = text.find(end)
    if start == -1 or stop == -1 or stop < start:
        raise ValueError(f"missing generated-section markers {begin} / {end}")
    return text[: start + len(begin)] + "\n" + body + text[stop:]


def ready_items(meta: dict[str, str], items: list[Item]) -> list[Item]:
    current_phase = meta.get("current-phase", "")
    by_id = {item.id: item for item in items}
    ready: list[Item] = []
    for item in items:
        if item.status != "ready":
            continue
        if item.deps and any(
            by_id[dep].status not in DONE_STATES for dep in item.deps if dep in by_id
        ):
            continue
        if current_phase and item.phase > current_phase:
            continue
        ready.append(item)
    return sorted(ready, key=lambda item: (PRIORITIES.index(item.priority), item.id))


def print_summary(meta: dict[str, str], items: list[Item]) -> None:
    counts = ", ".join(
        f"{status} {sum(1 for item in items if item.status == status)}" for status in STATUSES
    )
    print(f"OK: {len(items)} items ({counts}); phase {meta.get('current-phase', '?')}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--file", default=None, help="path to BACKLOG.md (default: repository root)"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="validate only (default)")
    group.add_argument(
        "--write", action="store_true", help="validate, then refresh Board and Index"
    )
    group.add_argument("--next", dest="list_next", action="store_true", help="list ready items")
    parser.add_argument("--json", action="store_true", help="machine-readable output for --next")
    parser.add_argument("--quiet", action="store_true", help="suppress warnings")
    args = parser.parse_args(argv)

    path = Path(args.file) if args.file else Path(__file__).resolve().parents[1] / "BACKLOG.md"
    if not path.is_file():
        print(f"error: {path} not found", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8")

    meta, items, errors, warnings = validate(text)
    if not args.quiet:
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)

    if args.list_next:
        if errors:
            print("error: fix validation errors before asking for ready work", file=sys.stderr)
            return 1
        ready = ready_items(meta, items)
        if args.json:
            print(
                json.dumps(
                    {
                        "phase": meta.get("current-phase"),
                        "items": [
                            {
                                "id": item.id,
                                "title": item.title,
                                "priority": item.priority,
                                "phase": item.phase,
                                "area": item.fields.get("area"),
                                "depends_on": item.deps,
                            }
                            for item in ready
                        ],
                    },
                    indent=2,
                )
            )
        else:
            if not ready:
                print("no ready items")
            for item in ready:
                deps = ", ".join(item.deps) if item.deps else "-"
                area = item.fields.get("area", "?")
                columns = (item.id, item.priority, item.phase, f"{area:<8}", item.title)
                print("  ".join(columns) + f"  [deps: {deps}]")
        return 0

    if errors:
        return 1

    if args.write:
        try:
            updated = replace_between(text, BOARD_BEGIN, BOARD_END, render_board(meta, items))
            updated = replace_between(updated, INDEX_BEGIN, INDEX_END, render_index(items))
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        if updated != text:
            with path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(updated)
            print(f"refreshed Board and Index in {path.name}")
        else:
            print(f"{path.name}: generated sections already current")

    print_summary(meta, items)
    return 0


if __name__ == "__main__":
    sys.exit(main())
