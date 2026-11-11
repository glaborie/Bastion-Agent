---
description: Take the next ready backlog item, implement it, verify it and close it
agent: build
---

Work exactly one backlog item, end to end, then stop. Never start a second item
in the same invocation.

Argument, when present: `$ARGUMENTS`

- An `IDEA-NNN` means work that item, but only if it appears in the ready list.
- An area name (`agent`, `gateway`, `db`, `infra`, `security`, `evals`, `docs`,
  `tooling`) means take the first ready item in that area.
- Empty means take the first ready item.
- Anything that does not match a ready item: say what the ready list contains,
  and stop. Do not substitute an `inbox`, `blocked` or later-phase item.

## 1. Select

Run:

```bash
uv run python scripts/check_backlog.py --next --json
```

If `items` is empty, print the current phase and `no ready items`, then stop.

Take the selected item (default: `items[0]`). Announce it in one line:
`IDEA-NNN  P?  area  title`.

## 2. Read before claiming

Read the item in `BACKLOG.md` and every ADR named in its `- spec:`. Read the
files the `**Outcome**` and `**Acceptance**` sections point at; do not plan from
the title alone.

If the acceptance criteria are not verifiable as written, do not guess and do not
implement a different task. Instead:

- set `- status: blocked`
- add `- blocked-by: acceptance criteria need clarification`
- append a `**Notes**` bullet naming exactly what is missing
- bump `- updated:` to today, run
  `uv run python scripts/check_backlog.py --write`, report, and stop.

## 3. Claim it before touching code

Set `- status: active` and `- updated: <today>` on the item, then run
`uv run python scripts/check_backlog.py --write`. This is what makes an
interrupted loop safe: a claimed item never comes back from `--next`.

## 4. Implement only the outcome

- Stay inside the item's `**Outcome**`. No drive-by refactors, no neighbouring
  ideas, no changes the acceptance criteria do not require.
- If ADR-008's phase gate or an ADR forbids the change, stop and set the item
  `blocked` with the reason instead of forcing it.
- If the change alters a decision recorded in an ADR, update that ADR in the same
  commit (`.opencode/skills/adr/SKILL.md` has the procedure) or supersede it.
- Work discovered on the way belongs in a `**Notes**` bullet on this item. Do not
  create new ids and do not implement it.

## 5. Verify against the repository gates

Run the gates covering what you changed, and the full set before closing:

```bash
uv run pytest -m "not integration"
uv run ruff check .
uv run mypy settings.py logging_setup.py db gateway agent scripts
uv run pylint settings.py logging_setup.py telemetry.py db gateway agent tests scripts
uv run python scripts/check_adrs.py
uv run python scripts/validate_tool_catalog.py --check
uv run python scripts/validate_rbac.py
uv run python scripts/recalculate_dread.py --check
uv run python scripts/check_backlog.py --check
```

For a `docs` item, `check_adrs.py` plus any script that reads the changed file is
enough; the full suite is still required before `status: done`.

`scripts/gate.sh` runs that whole list in a bounded pool and prints a metrics
table — per-step time, the one number that matters per step, and
`gate: 10/10 passed · wall 6m40s · sum 7m12s · 1.08x · jobs 4` — plus the
failing step's tail when one breaks. `--jobs N` caps the pool, `--serial` runs
it the old way, `--evals` adds the DeepEval gate, `--integration` the
database-backed tests.

A gate that fails is not a reason to weaken the gate. Fix the change; if the fix
is out of scope for this item, mark the item `blocked` with the failing gate in
`- blocked-by:` and stop.

## 6. Close only what you verified

Tick an acceptance box only when the command or observation in it actually
succeeded in this run. Then:

- every box ticked: `- status: done`
- any box unticked: leave `active`, add a `**Notes**` line on what remains

Either way bump `- updated:` to today and run
`uv run python scripts/check_backlog.py --write`. It must report `OK`.

## 7. Commit and report

One commit for one item, in the repository's existing style
(`feat(scope): ...`, `fix(scope): ...`, `docs(scope): ...`). The body must state
`Backlog: IDEA-NNN` and what was verified, and `git status` must show no
unrelated files.

Report one paragraph: the id, what changed, the gates that passed, the final
status, and anything you recorded in `**Notes**`. Then stop.
