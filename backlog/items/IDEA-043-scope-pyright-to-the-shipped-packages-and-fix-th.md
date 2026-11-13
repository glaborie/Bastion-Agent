### IDEA-043: Scope pyright to the shipped packages and fix the __doc__ indexing sites

- status: inbox
- priority: P3
- phase: v0.3
- area: tooling
- tags: pyright, tooling, typing
- depends-on: -
- spec: -
- created: 2026-11-13
- updated: 2026-11-13
- source: session on 2026-11-13 after `[tool.pyright] venvPath`/`venv` stopped masking pyright's view

**Problem**

`chore/pyright-venv` added `[tool.pyright] venvPath`/`venv`, so pyright now resolves
imports against `.venv` instead of reporting every third-party import as missing.
That exposed 51 pre-existing errors on the current tree with pyright 1.1.414: 39 in
`tests/` (`test_classifier.py` 8, `test_vault.py` 8, `test_approval_ws.py` 6,
`test_classifier_evals.py` 4, `test_auth_session.py` 3, `test_egress_evals.py` 3,
`test_tenant_isolation.py` 3, and others), the rest in `scripts/` (2) and the eval
metrics. Three groups behind them: duck-typed test doubles (`FakeBroker` passed where
`Redis` is declared, `SimpleNamespace` where a protocol is), redis-py's
`T | Awaitable[T]` coroutine unions that mypy only accepts because `gateway/auth/session.py`
casts them, and `deepeval.*` being `Any` to mypy via `ignore_missing_imports` while
pyright reads its real stubs (`success: bool | None`, a `__name__` property). The
repo's gate does not type-check `tests/` at all (`mypy settings.py logging_setup.py db
gateway agent scripts`), so none of that is signal about shipped code — it is noise
that hides the errors that do matter.

Separately, 12 of the errors are about `__doc__` being `str | None`:
`scripts/check_classifier_dispatch.py:144`, `scripts/benchmark_classifier_goldens.py:70`
and `scripts/demo_classifier.py:66` do `__doc__.splitlines()[0]` for
`ArgumentParser(description=...)`. mypy special-cases `__doc__` as `str`, so the gate
never sees it; under `python -OO` the docstring is stripped and those three entry
points raise `AttributeError` on first use.

**Outcome**

Pyright's default invocation analyses the shipped packages only (`db`, `gateway`,
`agent`, `scripts`) and reports zero errors, with the mock-heavy tests excluded by
`[tool.pyright] include`/`exclude` rather than by silencing rules. The three
`__doc__` sites fall back to a literal description when the docstring is absent, so
every script still starts under `python -OO`. The pyright configuration states which
packages it covers so a future module outside them is a deliberate decision.

**Acceptance**

- [ ] `uvx --from pyright pyright` exits 0 with no errors and no warnings on the tree, with `[tool.pyright] include` naming `db`, `gateway`, `agent` and `scripts` and `exclude` naming `tests` (and `.venv`)
- [ ] the same invocation on `tests/` is not part of the default run, and the config comment says why: the doubles are duck-typed and mypy, not pyright, is the gate
- [ ] `python -OO scripts/check_classifier_dispatch.py --help`, `python -OO scripts/demo_classifier.py --help` and `python -OO scripts/benchmark_classifier_goldens.py --help` exit 0 and print a usage line instead of raising on `__doc__`
- [ ] a test or script-level assertion covers the `-OO` case for one of the three, so a fourth `__doc__` site cannot come back unnoticed
- [ ] `uv run --no-sync ruff check .`, `uv run --no-sync ruff format --check .` and `uv run --no-sync mypy settings.py logging_setup.py db gateway agent scripts` stay clean, and `scripts/gate.sh` stays 12/12

**Notes**

- Decision recorded on 2026-11-13: mock-heavy tests stay out of pyright's default run. They are already outside the mypy gate, and their failures are double/protocol mismatches rather than defects; scoping pyright to the shipped packages makes its output reviewable.
- pyright is not a step in `scripts/gate.sh` and this item does not add it. CI and the gate stay on mypy; pyright is the editor's second opinion, and the acceptance is checked by hand.
- Measured, not assumed: 51 errors with pyright 1.1.414 on `origin/master` after `53ab5e5`, broken down by rule as `reportGeneralTypeIssues` 15, `reportCallIssue` 13, `reportOptionalMemberAccess` 12, `reportArgumentType` 4, `reportReturnType` 2, `reportIncompatibleMethodOverride` 2, `reportOptionalSubscript` 2, `reportOperatorIssue` 1.
- `spec` is `-`: no ADR governs type-checker configuration or editor tooling. If that changes, ADR-016 (supply chain and scanning) is the nearest neighbour but does not cover it.
