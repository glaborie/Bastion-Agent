### IDEA-088: Let pylint use the available cores in the gate

- status: active
- priority: P2
- phase: v0.5
- area: tooling
- tags: tooling, ci, performance
- depends-on: -
- spec: -
- created: 2026-11-19
- updated: 2026-11-19
- source: operator observation watching scripts/gate.sh on 2026-11-19

**Problem**

The gate's `pylint` step is its longest slot — 1m01s-1m51s across the last runs, while the whole pool of fourteen steps is otherwise spread over four jobs. Pylint runs every target in one process even though it ships a `--jobs` option, so a full-target run costs 48.07s on this eight-core host. Pytest is already parallelised (`-n auto --dist loadfile` unless `TEST_DATABASE_URL` forces one database), so pylint is the only step that leaves cores idle by design.

**Outcome**

`[tool.pylint.main]` sets `jobs = 0` (auto), so the gate, the documented direct command and CI all lint in parallel without a separate flag. `duplicate-code` (R0801), the one cross-module checker parallel mode complicates, is already disabled in this repository.

**Acceptance**

- [ ] `[tool.pylint.main]` sets `jobs = 0` and a full-target run still rates `10.00/10` and exits 0
- [ ] the same full-target run completes in less wall time than the 48.07s single-process baseline recorded in the item
- [ ] `scripts/gate.sh` passes 14/14 with no other change

**Notes**

- Baseline measured on 2026-11-19 with `pylint settings.py logging_setup.py telemetry.py db gateway agent tests scripts`: 48.07s single-process, 30.93s with `--jobs=0`, both rated 10.00/10. The gain is bounded by startup per module, so the item does not claim linear scaling.
- Pytest is already parallel: `scripts/gate.sh` passes `-n auto --dist loadfile` when no shared test database is configured, and CI shards it 2 ways. Only the `TEST_DATABASE_URL` path runs serially, because the DB fixtures truncate tables per module and two workers would clobber each other.
