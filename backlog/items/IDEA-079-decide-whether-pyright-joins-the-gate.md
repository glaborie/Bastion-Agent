### IDEA-079: Decide whether pyright joins the gate (it is clean today)

- status: done
- priority: P3
- phase: v0.5
- area: tooling
- tags: pyright, tooling, typing, ci
- depends-on: -
- spec: -
- created: 2026-11-18
- updated: 2026-11-20
- source: session on 2026-11-18, after a root pyrightconfig.json briefly overrode the committed [tool.pyright]

**Problem**

IDEA-043 (done) recorded pyright as "the editor's second opinion", set
`[tool.pyright]` in `pyproject.toml` to `include = ["db", "gateway", "agent",
"scripts"]` with `tests` excluded, and deliberately kept pyright out of the
gate. Since then nobody has re-checked whether that exclusion still costs
anything: `mypy strict` gates the shipped code, but no committed artefact
records pyright's actual result under the recorded scope.

Measured 2026-11-18 (pyright 1.1.414, `uvx --from pyright pyright
--outputjson`): under the committed `[tool.pyright]` scope, **103 files, 0
errors, 0 warnings, 15.8 s**. So pyright is clean as configured — the finding
to record is the absence of a decision about its place, not a defect backlog.

The one real incident found while measuring: a root `pyrightconfig.json`
carrying only `venvPath`, `venv`, `pythonVersion` and an `exclude` silently
outranks `[tool.pyright]`, widened the scope to the whole tree (182 files, tests
included) and produced 45 errors, all of them outside the committed `include`.
The file was deleted in the same session, so that risk is a configuration
hazard, not a live state.

**Outcome**

Recorded, in this item or a one-line addition to IDEA-043's decision, whether
pyright stays editor-only or joins `scripts/gate.sh`/CI as a second checker
beside `mypy strict`, with the reason. If it joins, its scope and run time are
part of the decision (103 files in ~16 s is the number to judge). The
`pyproject.toml` `[tool.pyright]` block remains the single source of scope: no
root `pyrightconfig.json`, and `git status` shows none.

**Decision**

2026-11-20: pyright stays editor-only; it does not join `scripts/gate.sh` or CI.
Under the committed scope it reports 0 errors and 0 warnings over 110 files in
~11 s, and `mypy strict` already gates the same four packages, so a second
checker over the same code buys no finding today and costs a gate step, a second
suppression dialect (`# pyright: ignore[...]` beside `# type: ignore`), and an
unpinned tool (`uvx --from pyright`) in a pipeline that pins everything else.
What that leaves unguarded: a diagnostic only pyright's rules would raise
(its defaults are a subset of `mypy strict`, so none is known today), and the
scope hazard below — a stray root `pyrightconfig.json` widens the run to 182
files and 45 errors, and nothing in CI would see it because nothing runs
pyright. That gap is accepted for an editor tool at `P3`; the file is absent
today and its absence is a hand check, not a gate. IDEA-043 recorded the scope
this decision keeps and its Notes say the same thing; `spec: -` because no ADR
governs type-checker configuration.

**Acceptance**

- [x] The decision is written down: pyright stays editor-only (naming what that leaves unguarded) or it runs in the gate (naming scope and the ~16 s cost)
- [x] `uvx --from pyright pyright --outputjson` under `[tool.pyright]` still reports the recorded count (0 errors, 103 files) or the item records the new one with the commit that moved it
- [x] No root `pyrightconfig.json` exists; `[tool.pyright]` is the only scope, and its comment states why `tests` is excluded
- [x] If pyright joins CI, the wiring lands in its own PR and `scripts/gate.sh` documents it; `uv run --no-sync mypy ...`, `uv run --no-sync ruff check .` and `scripts/gate.sh` stay green
- [x] IDEA-043 is referenced from the decision so the two records do not contradict each other

**Notes**

- The trap worth remembering: `pyrightconfig.json` at the repo root takes precedence over `[tool.pyright]` in `pyproject.toml`, so a throwaway file can silently rewrite scope, exclusions and environment for every developer who has it. IDEA-043's scope only holds while that file is absent.
- Numbers measured 2026-11-18: committed scope 103 files / 0 errors / 15.8 s; with the stray root file 182 files / 45 errors (tests and packages outside `include`); without any venv wiring 371 errors, nearly all `reportMissingImports`. The first two runs differ only by scope, not by code.
- `spec: -`: no ADR governs type-checker configuration. ADR-016 is the nearest neighbour (tooling in CI) and does not cover it, so the decision lives here rather than being forced into a reference.
- `P3`/`v0.5`: nothing ships wrongly today — pyright is clean in its scope and `mypy strict` still gates. `area: tooling` for IDEA-043's reason.
- 2026-11-20, the count moved: the recorded 103 files was `f444a39` (2026-11-18). Today it is 110 files / 0 errors / 0 warnings / 11.1 s, from `f356701` (+2, `gateway/routers/openai_compat.py` and `chat_tracing.py`), `e255e02` (+2, `db/agents.py` and `gateway/auth/agents.py`), `da6f811` (+2, `scripts/__init__.py` and `scripts/_env.py`) and `24a6bc1` (+1, `scripts/dev/backup_dev.py`). Same pyright 1.1.414, so the delta is added code, not a tool change.
- 2026-11-20, seen while gating: `scripts/dev/worktree.sh` links `.env` but not `.env.vault`, so a fresh worktree's `infra` step and `test_audit_witness` fail on the IDEA-076 secrets until the file is linked by hand. Worktree setup, not this item; worth its own entry.
- 2026-11-20, decision recorded above, no code or config change: `pyproject.toml` `[tool.pyright]` already carries the scope and the `tests` rationale, and `git ls-files` shows no `pyrightconfig.json`. No ADR was created — IDEA-043's Notes explain why type-checker configuration has none.
