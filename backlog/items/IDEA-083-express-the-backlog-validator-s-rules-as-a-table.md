### IDEA-083: Express the backlog validator's rules as a table instead of one branch per rule

- status: ready
- priority: P3
- phase: v0.5
- area: tooling
- tags: backlog, tooling, refactor, validator
- depends-on: -
- spec: -
- created: 2026-11-18
- updated: 2026-11-19
- source: session request on 2026-11-18, refactoring scan of scripts/check_backlog.py

**Problem**

`scripts/check_backlog.py` is 739 lines, and its two hottest functions carry almost all of it: `validate()` (line 236) is 178 lines of near-identical `if` blocks — one per required field, enum, tag, date, dependency, status and acceptance rule — and `main()` (line 569) is 167 lines that repeat the same load-errors-then-exit-2 prologue in every mode. Since IDEA-041 made this script the single enforcement point for the item store (`scripts/gate.sh` runs `--check`, `scripts/dev/worktree.sh` claims through `--write`, and `/next`, `/idea` and `/handoff` all call it), every new rule adds another branch and another hand-written message string, and that message text is exactly what an agent reads at merge time when a duplicate id or a refused transition is diagnosed. Nothing is broken today; the cost is that a rule and its message can drift apart, and no single place in the file shows the rule set.

**Outcome**

Validation rules are data — a table of predicate plus message plus severity (or an equivalent declarative shape) — so adding a rule is one entry and its message cannot be separated from its check. Every existing error and warning message, exit code (0 valid, 1 validation error, 2 unreadable store), `--json` payload field and `OK:` summary line stays byte-identical, and `--next`, `--list`, `--set`, `--write`, `--new`, `--next-id` and `--check` keep their current output and their refusal cases: an invalid `--set` transition writes nothing, `--new` on an existing path fails instead of overwriting, and a store with validation errors still refuses to list. This is a behaviour-preserving refactor only — no rule added, none removed, none reworded.

**Acceptance**

- [ ] `uv run pytest tests/test_backlog_store.py -q` passes, with no existing test edited to accommodate the refactor
- [ ] `uv run python scripts/check_backlog.py --check` reports OK on the real corpus, and its stdout and stderr diffed against the output captured before the change are empty (same `OK:` line, same warnings)
- [ ] A broken fixture per rule class — missing field, bad enum, duplicate id, dangling and cyclic `depends-on`, `done` with an unticked box, `blocked` without `blocked-by`, bad `wip-limit`, duplicate title — still produces the pre-refactor error text, one test per class asserting the exact old string
- [ ] `uv run python scripts/check_backlog.py --next --json`, `--list inbox`, `--set` and `--write` print the same output before and after the change, and `--set` still refuses a transition the validator would reject without writing the file
- [ ] `uv run mypy scripts/check_backlog.py` reports no issues and `uv run pylint scripts/check_backlog.py` stays at 10.00/10

**Notes**

- Classification: `P3` stands. Nothing user-visible is broken and the gate is green, so this is maintainability with no phase commitment; `phase: v0.5` is recorded because `backlog/config.toml` has `current-phase = "v0.5"` and the intake rubric sends a change with no obvious home to the current phase. If triage prefers "no commitment", the phase can be moved without touching the rest.
- `spec: -` because no ADR fixes the item schema: ADR-008 only names the one-file-per-item store and the phase policy, and IDEA-041 (status `done`) is the layout decision this refactor inherits rather than a schema decision. The field set is defined by this script and the intake skill, which is the gap the table would make visible.
- Deduplication: grepped `backlog/items/` for `check_backlog`, `validator`, `backlog tooling` and the module name. IDEA-041 is done and owns the storage layout, IDEA-063 is `scripts/dev/cleanup.sh`, and the other hits are gate-command lines inside acceptance boxes. No item owns the validator's rule structure, so nothing was merged.
- Out of scope but worth knowing: `pyproject.toml` disables pylint `too-many-statements` with the comment "one flat sweep over every backlog field"; a table may make that disable removable, but removing it is a separate change.
- Open question for the implementer: whether the table should also drive the `--set` pre/post `validate()` diff in `main()`, or `--set` keeps calling `validate()` unchanged. Either is acceptable; no new refusal may be introduced.
