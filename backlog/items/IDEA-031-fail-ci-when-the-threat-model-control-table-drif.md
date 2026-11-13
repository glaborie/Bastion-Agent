### IDEA-031: Fail CI when the threat-model control table drifts from the tree

- status: done
- priority: P2
- phase: v0.3
- area: tooling
- tags: ci, threat-model, drift, documentation
- depends-on: -
- spec: -
- created: 2026-11-12
- updated: 2026-11-13
- source: security posture review, 2026-11-12

**Problem**

`THREAT_MODEL.md` §4 is the first artefact an auditor reads and it is hand-maintained with no gate: line 95 still says "Test and eval gate in CI | PLANNED | CI runs pylint with `--exit-zero` only" although `.github/workflows/ci.yml` has run the full suite plus the zero-tolerance eval job for several phases, and the Falco row appears twice (lines 94 and 98). Every other policy document has a checker — `scripts/check_adrs.py`, `scripts/check_backlog.py`, `scripts/validate_tool_catalog.py`, `scripts/validate_rbac.py` — so the control matrix is the one place where a stale claim survives CI.

**Outcome**

`scripts/check_threat_model.py` makes the matrix falsifiable: duplicate control names fail, a LIVE row must name a path that exists and a test file that exists, and a PLANNED row that names a path already implementing the control fails too, so a shipped control cannot stay PLANNED. It runs in the `quality` job and in `scripts/gate.sh`, and the two current defects are corrected in the same change.

**Acceptance**

- [x] `uv run python scripts/check_threat_model.py --check` exits non-zero against the current file (duplicate Falco row, false PLANNED eval row) and zero after the fix
- [x] `tests/test_threat_model.py` covers a duplicate row, a LIVE row naming a missing path, a LIVE row naming a missing test, and a PLANNED row whose named path exists
- [x] `.github/workflows/ci.yml` runs it in `quality` beside the other policy scripts, and `scripts/gate.sh` includes it
- [x] `THREAT_MODEL.md` §4 has one row per control, no control marked PLANNED that the tree implements, and the header says how to keep the check green
- [x] `uv run pytest -q`, ruff, mypy, pylint and the existing policy scripts stay green

**Notes**

- Deduplication: grepped `BACKLOG.md`, `docs/adr/` and `scripts/` for `check_threat`, `control status`, `control table` and `drift`. IDEA-010 (restating an ADR-006 decision) and IDEA-011 (the `CONTROL.md` rate-limit claim) are the same genre of document reconciliation but each fixed one document by hand; nothing generalises the check. IDEA-019 updated the T11 rows inside the supply-chain work and left the gate absent, which is why the §4 table drifted again. `spec: -` because no ADR governs the threat model's lifecycle; `ADR-Index` is the nearest owner and could be cited instead.
- Classification: `P2`/`v0.3`/`tooling`. A defect in shipped documentation, so the current phase; `P2` because no runtime control is affected and the drift misleads a reader rather than an attacker. `area: tooling` because the deliverable is a script and CI wiring; `docs` is the alternative reading.
- Verification, 2026-11-13. Before the fix, `uv run python scripts/check_threat_model.py --check` exited `1` with 15 errors, including `line 98: duplicate control 'Runtime syscall detection (Falco, opt-in `security` profile)' (first at line 94)`; after the table edit it exits `0` with `OK: 17 control rows consistent with the tree`. `tests/test_threat_model.py` -> 6 passed (duplicate, missing path, missing test, PLANNED path that exists, a consistent row, and the repository table itself). `scripts/gate.sh --changed` -> 12/12: ruff check and format clean, mypy clean on 83 files, pylint 10.00/10, `pytest` 665 passed / 61 skipped / 18 warnings, and the `adrs`, `tool-catalog`, `rbac`, `infra`, `dread`, `threat-model` and `backlog` steps green.
- Limit of the rule, stated rather than hidden: the stale eval row said "CI runs pylint with `--exit-zero` only" and named no path, so no static rule can see that prose is false — it was corrected by hand here. The mechanical rule covers the case that bit twice: a row that names a path the tree already has (LIVE with a missing path/test, or PLANNED with an existing path). A future reviewer still has to move a PLANNED control after writing its implementation path down, which is exactly what the "keep it green" paragraph tells them to do.
- Files changed: `scripts/check_threat_model.py`, `tests/test_threat_model.py`, `THREAT_MODEL.md` (§4 table plus the green-keeping paragraph), `.github/workflows/ci.yml` (`quality` job), `scripts/gate.sh`, `README.md` (script table and verification block), `.opencode/commands/next.md` (gate list).
- Two doc corrections landed with the gate rather than after it: the Falco row appears once, and the "Test and eval gate in CI" row is LIVE against `.github/workflows/ci.yml` plus `tests/test_dlp_evals.py`/`tests/test_egress_evals.py` instead of claiming CI only lints with `--exit-zero`. The `docs/tools/v1.json` row now names `agent/tools/catalog.py` and `tests/test_tool_catalog.py` instead of prose, and the audit row points at `gateway/routers/audit.py` rather than the route string `/api/audit/verify`, which is not a file.
