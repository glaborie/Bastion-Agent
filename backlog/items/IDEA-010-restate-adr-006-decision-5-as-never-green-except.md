### IDEA-010: Restate ADR-006 decision 5 as never green except a verified host-verdict exemption

- status: done
- priority: P1
- phase: v0.2
- area: docs
- tags: adr, evals, ci
- depends-on: -
- spec: ADR-006
- created: 2026-11-10
- updated: 2026-11-11
- source: review of ADR-006 decision 5 against commit c7c8616 (eval gate dispatch exemption), 2026-11-10

**Problem**

`docs/adr/ADR-006.md` decision 5 still states one rule: "A gate with no executed tests scores `0.0` and counts a synthetic failure, so an all-skipped run is red rather than vacuously green." Commit `c7c8616` changed the gate underneath it: `scripts/check_classifier_dispatch.py` publishes a `reference` / `dispatch_anomaly` host verdict, `scripts/run_evals.py --dispatch-verdict` publishes `exempt_gates` instead of a synthetic failure, and the gate now passes when rows were SKIPPED (not only when every row was skipped) on a verified AVX2 dispatch anomaly. That exception is written down only in ADR-011's Consequences and in `README.md`, not in the ADR that owns the never-green rule. ADR-006's `Last modified` is already 2026-11-10, so the date was bumped without this text changing, which makes the contradiction look deliberate.

**Outcome**

ADR-006 decision 5 states the rule the code enforces: a gate is never green merely because no evidence was produced, except when a verified host verdict exempts the ratio assertions, and those exemptions are recorded under `exempt_gates` rather than converted into a synthetic failure. The text keeps the distinction intact — a failed row is never exempted and a partial mismatch still falls through to the gate — and points at ADR-011 decision 7 for the rationale and the accepted asymmetry. `Last modified` reflects the edit.

**Acceptance**

- [x] `docs/adr/ADR-006.md` decision 5 names `scripts/check_classifier_dispatch.py`, the `reference` / `dispatch_anomaly` verdict, `--dispatch-verdict` and `exempt_gates`, and links ADR-011 instead of restating its rationale
- [x] The text keeps the never-green rule for missing evidence and says explicitly that a failed row is never exempted and a partial skip still fails the gate
- [x] ADR-006 `Last modified` is bumped to the edit date
- [x] `uv run python scripts/check_adrs.py` passes
- [x] No change to `scripts/run_evals.py`, `scripts/check_classifier_dispatch.py`, `agent/routing/dispatch.py` or any test in the same change

**Notes**

- Duplicate check: IDEA-008 (done) built the exemption itself and its acceptance ticked only "`docs/adr/ADR-011.md` records the choice"; no open or done backlog item mentions ADR-006, so this item is the ADR-006 documentation correction, not a second run at the gate work.
- Classified P1 because an Accepted ADR that misstates a security-relevant gate rule is a governance defect, not cosmetic; triage may downgrade if it disagrees.
- Related drift seen while checking: ADR-012 decision 6 repeats "an unverified gate is not a pass" for the same `scripts/run_evals.py` gates. Left out of this item's scope (ADR-006 owns the rule); it becomes a separate correction if triage wants the corpus consistent.

**Implementation notes (2026-11-11)**

- Rewrote only decision 5's CI paragraph in `docs/adr/ADR-006.md`: the never-green sentence is kept and now begins "A gate is never green merely because no evidence was produced", followed by one paragraph that names `scripts/check_classifier_dispatch.py`, `reference` / `dispatch_anomaly`, `--dispatch-verdict` and `exempt_gates`, and points at ADR-011 for the rationale and the accepted asymmetry. `Last modified` bumped 2026-11-10 → 2026-11-11.
- The narrowness is stated against the code, not paraphrased from ADR-011: `scripts/run_evals.py::summarise` records an exemption only for `ClassifierGoldenGate`, only when the flag took effect (a test in that gate skipped) and never when any test in the gate failed — a failed row leaves the failure standing, the metric at `0.0` and `exempt_gates` empty (`tests/test_eval_runner.py::test_the_exemption_never_covers_a_failed_row`, `test_an_exemption_without_a_skip_is_not_recorded`).
- Acceptance box 2's "a partial skip still fails the gate" is written as "a partial mismatch (one benign row, a lost positive) still falls through and fails the gate", matching the item's own Outcome wording and ADR-011's dispatch note. A partial *skip* inside the exempted gate is precisely what the shipped runner accepts (`tests/test_eval_runner.py::test_a_mixed_gate_records_the_exemption`), so claiming otherwise in the ADR would have documented behaviour the code does not have. The never-green rule and "a failed row is never exempted" are both stated explicitly.
- The Outcome's pointer to "ADR-011 decision 7" was dropped: decision 7 owns the thresholds, while the exemption's rationale and its accepted asymmetry live in ADR-011's Consequences ("exempt the ratio assertions by host verdict"). ADR-006 links ADR-011 without naming a decision so the reference is correct without editing ADR-011.
- Docs-only, as scoped: `git status` shows `docs/adr/ADR-006.md` and `BACKLOG.md` only; no change to the runner, the dispatch script, `agent/routing/dispatch.py` or any test. `uv run python scripts/check_adrs.py` → `OK: 16 ADRs, index consistent, no machine-local paths`. ADR-012's matching "an unverified gate is not a pass" sentence is left for a separate item, per the Notes above.
