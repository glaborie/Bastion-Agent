### IDEA-079: Decide whether pyright joins the gate (it is clean today)

- status: active
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

**Acceptance**

- [ ] The decision is written down: pyright stays editor-only (naming what that leaves unguarded) or it runs in the gate (naming scope and the ~16 s cost)
- [ ] `uvx --from pyright pyright --outputjson` under `[tool.pyright]` still reports the recorded count (0 errors, 103 files) or the item records the new one with the commit that moved it
- [ ] No root `pyrightconfig.json` exists; `[tool.pyright]` is the only scope, and its comment states why `tests` is excluded
- [ ] If pyright joins CI, the wiring lands in its own PR and `scripts/gate.sh` documents it; `uv run --no-sync mypy ...`, `uv run --no-sync ruff check .` and `scripts/gate.sh` stay green
- [ ] IDEA-043 is referenced from the decision so the two records do not contradict each other

**Notes**

- The trap worth remembering: `pyrightconfig.json` at the repo root takes precedence over `[tool.pyright]` in `pyproject.toml`, so a throwaway file can silently rewrite scope, exclusions and environment for every developer who has it. IDEA-043's scope only holds while that file is absent.
- Numbers measured 2026-11-18: committed scope 103 files / 0 errors / 15.8 s; with the stray root file 182 files / 45 errors (tests and packages outside `include`); without any venv wiring 371 errors, nearly all `reportMissingImports`. The first two runs differ only by scope, not by code.
- `spec: -`: no ADR governs type-checker configuration. ADR-016 is the nearest neighbour (tooling in CI) and does not cover it, so the decision lives here rather than being forced into a reference.
- `P3`/`v0.5`: nothing ships wrongly today — pyright is clean in its scope and `mypy strict` still gates. `area: tooling` for IDEA-043's reason.
