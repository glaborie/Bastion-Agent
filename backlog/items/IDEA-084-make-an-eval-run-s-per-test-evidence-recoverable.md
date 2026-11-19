### IDEA-084: Make an eval run's per-test evidence recoverable from the harness

- status: ready
- priority: P2
- phase: v0.5
- area: evals
- tags: evals, tooling, pytest, observability, ci
- depends-on: -
- spec: ADR-006
- created: 2026-11-18
- updated: 2026-11-19
- source: session on 2026-11-18, after the first recorded run (`run_id 1e39853cf621489c9885921566b5af31`, 250/250, all three metrics `1.0`) left no way to say which tests produced it

**Problem**

`scripts/run_evals.py` publishes only an aggregate: `artifacts/evals/latest.json`
carries `run_id`, counts, three metric floats and `git_sha`, and
`GET /api/evals/latest` serves exactly that. `run_id` is a label with no other
reader — nothing is keyed on it, no history is kept, and the file is replaced
atomically on the next run — so a recorded run cannot answer "which tests ran,
and did any of them skip or get exempted?"

Two concrete defects sit behind that:

1. **The documented pytest passthrough does not work.** `main()` declares a
   `pytest_args` positional (`nargs="*"`, help text "extra pytest arguments,
   e.g. `-k dlp`"), but it is parsed with `parse_args`. Any option is rejected
   before pytest starts: `uv run python scripts/run_evals.py -k dlp_evals` exits
   with `run_evals.py: error: unrecognized arguments: -k`. Only bare words get
   through, and passing a module path that is already in `GATES` would run it
   twice. `--help` advertises a feature that cannot be used, and the only way to
   see per-test detail today is to bypass the harness and run pytest against the
   three modules by hand.
2. **No per-test evidence is persisted.** The collector records a final outcome
   per node id in memory, then `summarise()` reduces it to counts and drops the
   node ids. No JUnit XML, no per-test list, no log is written beside the
   report. A red gate therefore reports `failed: 1` (possibly synthetic, for a
   gate where nothing ran) with no test name; the only surviving detail is the
   stdout of that one invocation, which is gone once the terminal or CI log
   scrolls away. `scripts/gate.sh --evals` does keep `artifacts/gate/<run>/evals.log`,
   but that path exists only for local gate runs, not for a bare `run_evals.py`
   run — which is the documented way to record a run.

Measured for context (2026-11-18): the three gate modules hold 48
(`test_dlp_evals.py`), 188 (`test_egress_evals.py`) and 14
(`test_classifier_evals.py`) tests; `--collect-only` reconstructs the inventory,
but it re-derives it from the tree and cannot prove anything about a past run.

**Outcome**

One recorded run carries its own per-test evidence, and the documented flags
work:

- `pytest_args` accepts what `--help` says it accepts (`-k`, `-v`, `-x`,
  `--tb=`, `-ra`) and forwards them to pytest unchanged, so a caller can narrow
  a run without editing the script; a bare positional word still behaves as it
  does today.
- Every run writes a machine-readable per-test record next to the summary —
  `artifacts/evals/latest-junit.xml` (or the equivalent `report.xml` the
  harness already knows about), atomically replaced like `latest.json`, holding
  every node id with its outcome (`passed`/`failed`/`skipped`) and the skip
  reason. `tests/test_evals_*.py` that assert the report shape stay green.
- The report's `run_id` becomes answerable: the summary names the evidence file
  it wrote (or a fixed sibling name), so `run_id` plus that file reconstructs
  which module contributed which metric and which tests skipped, without a
  second run and without keeping history.

The published JSON contract does not change: `gateway/evals.py`'s
`EvalRunSummary` keeps its fields and validators, `/api/evals/latest` returns the
same keys, and the never-green rule (ADR-006 decision 3) is untouched — a gate
with no executed test still scores `0.0` and counts a synthetic failure. Run
history (retaining past runs) is deliberately out of scope; this makes one run
explainable, not a database.

**Acceptance**

- [ ] `uv run python scripts/run_evals.py -k test_dlp_evals` runs only that module's tests and exits 0; the same invocation works for `-v`, `-x` and `--tb=short`, and `scripts/run_evals.py --help` still renders
- [ ] A deliberately broken gate row makes the run write evidence that names the failing node id and the module it belongs to, and the summary still reports one failure with the metric at `0.0` (never-green rule intact)
- [ ] The per-test evidence file is written atomically to the configured report directory, is world-readable (`0o644`, like `latest.json`), and carries every node id with `passed`/`failed`/`skipped` plus the skip reason
- [ ] `artifacts/evals/latest.json` still validates against `gateway/evals.py`'s `EvalRunSummary` unchanged, and `GET /api/evals/latest` returns the same keys for a fresh run
- [ ] `uv run pytest -m "not integration"` passes, and `uv run python scripts/run_evals.py` on the models-bearing checkout still reports 250/250 with all three metrics at `1.0`
- [ ] `uv run mypy scripts`, `uv run pylint scripts`, `uv run ruff check .` and `scripts/gate.sh` stay green

**Notes**

- Evidence for the two defects, observed in one session on 2026-11-18: `uv run python scripts/run_evals.py -k dlp_evals` → `error: unrecognized arguments: -k`; `artifacts/evals/latest.json` after a green run holds 397 bytes and no node ids.
- `spec: ADR-006`: decision 3 owns the harness, the never-green rule and the report file. The change adds evidence beside the report and must not alter what the report means; ADR-006 needs no edit unless the summary gains a field, in which case the ADR moves with it.
- Nearest existing pattern: `scripts/gate.sh` already writes per-step logs and `summary.md` under `artifacts/gate/<run>/`, and CI runs pytest with `--junitxml=pytest-report.xml` (`.github/workflows/ci.yml`). Reusing that shape and name keeps the two harnesses legible together rather than inventing a third format.
- `P2`/`v0.5`: nothing ships wrongly today — the gates themselves are correct and green — but the artefact of a security gate that nobody can explain is exactly the evidence gap ADR-006 exists to close, and this is a small, self-contained change to one script.
- Capture only: no test, script or document change is part of this item.
