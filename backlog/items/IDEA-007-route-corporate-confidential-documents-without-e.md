### IDEA-007: Route corporate-confidential documents without explicit markers to the local model

- status: done
- priority: P1
- phase: v0.2
- area: agent
- tags: classifier, calibration, dlp, routing
- depends-on: -
- spec: ADR-011
- created: 2026-11-10
- updated: 2026-11-11
- source: live traffic through POST /v1/chat on 2026-11-10

**Problem**

The classifier only routes to `local-llama` when it sees a marker. Measured on
the live stack today, "Q3 revenue forecast assumes a hiring freeze through
December" reached `cloud-primary` as PUBLIC with confidence 0.9875, and a
supplier indemnity clause reached it with 0.9804. The first matches only the
`commercial` rule at weight 2.0, which the deterministic floor scores
`2/(2+2)=0.50` against the 0.55 threshold (`agent/routing/classifier.py`,
`_classify_rules`); an indemnity clause of the same shape matches no rule at all
(measured: 0 markers). The ONNX ensemble cannot close the gap by design — it was
trained on harm, so secrecy that contains nothing harmful reads as safe
`public_content`. The documents a company most wants kept in-house —
forecasts, margin analysis, contracts — therefore leave for the cloud unless
someone happens to type "confidential".

**Outcome**

A prompt that is corporate-confidential by content, with no explicit marking,
routes to the local model or is refused, and the verdict with its evidence is
visible in the audit ledger and on the trace's server span. The documented
"single weight-2 marker stays borderline" policy is either revised with a
recorded rationale or replaced, and the evidence corpus is extended with this
class of text.

**Acceptance**

- [x] `uv run pytest tests/test_classifier.py tests/test_classifier_evals.py -q` passes with a new assertion for an unmarked commercial prompt (a revenue forecast, a contract clause); no existing assertion is deleted to make the new one pass
- [x] `uv run python scripts/demo_classifier.py "<sample>"` prints the new verdict and the rule or ensemble evidence that produced it, for both sample classes
- [x] `docs/adr/ADR-011.md` records the choice (rule weight, new rule set, or a second model head), the re-measured benign false-positive and recall numbers, and the gap that remains
- [x] The corpus gains rows of this class taken from measured live traffic, and ADR-011 still states it is calibration, not held-out evidence
- [x] A live `POST /v1/chat` with such a prompt shows `bastion.classification=CONFIDENTIAL` and `bastion.route=local-llama` on the server span in the trace store

**Notes**

- Implemented at explicit request (the item was `inbox`, and the ready list was empty); the decision recorded here is the "revise the documented policy with a rationale" option, not weight tuning alone.
- Originally recorded as documented policy, not a crash: the `_RULES` comment pinned the 0.50 outcome deliberately and `test_a_single_codename_is_borderline_and_stays_public` enforced the same threshold for `codename`, so the fix had to be a decision with a false-positive budget attached, not an inline edit.
- Options seen at capture: raise `commercial` to 3.0 (a lone forecast marker then scores 0.60), add a contract/legal rule set, or train a corporate-secrecy head. Weight tuning alone could not cover the indemnity case, which matched nothing — hence both the weight raise and the new rule set.
- The misroute was spotted while reviewing trace telemetry from a realistic traffic run: it appeared as a PUBLIC `cloud-primary` turn in OpenLit. Related to IDEA-003 (classifier latency) through the same ADR-011 operating point.
- Policy now: every domain marker weighs 3.0, so one marker of confidential substance crosses the 0.55 threshold on its own. `commercial` moved 2.0 → 3.0 and `contract_legal` is new at 3.0 (`indemnif*`, `indemnit(y|ies)`, `force majeure`, `governing law`, `limitation of liability`, `unlimited liability`, `liability cap`, `master services agreement`, `warranty clause`, `warranty period`). `codename` is the only remaining weight-2 marker, so "a single weight-2 marker stays borderline" is now true of a project name alone — an identifier with no confidential content around it, unlike a forecast or an indemnity clause, which *is* the content. The `_RULES` comment and `test_a_single_codename_is_borderline_and_stays_public` keep enforcing that.
- Measured over the 85-row corpus with the pinned int8 graphs: the rules floor blocks 18 of 42 asserted must-block positives (0.429, was 16/40 = 0.400) and flags none of the 26 rows the corpus expects to stay `PUBLIC` (0.000, unchanged); the end-to-end gate blocks 42/42. The five accepted over-routes (term sheet, board meeting, source-code review, salary benchmark, merger news) are unchanged. `tests/test_classifier_evals.py` pins the three counts so the FP budget cannot drift silently.
- Corpus 83 → 85 rows: `corporate-forecast-unmarked-084` (the verbatim live prompt, which the model alone still calls `public_content` at 0.999) and `corporate-indemnity-clause-085` (its model-only confidence reproduces the measured 0.9804). ADR-011 still labels the corpus calibration, not held-out evidence, and now records the expansion and the numbers.
- Live verification against the running stack (gateway and worker images rebuilt with the change): `POST /v1/chat` for the forecast returned CONFIDENTIAL / local-llama / 0.6 / reason `matched: commercial`, and for the indemnity clause CONFIDENTIAL / local-llama / 0.6 / `matched: contract_legal`; both spans are in the OpenLit trace store with `bastion.classification=CONFIDENTIAL`, `bastion.route=local-llama` and the matching `gen_ai.conversation.id`.
- Remaining gap (recorded in ADR-011 decision 4): the floor is a vocabulary gate, so corporate text phrased without any of these markers — the "client's account at the Zurich Kantonalbank" paraphrase already carried as a `known_gap` row — still reads as public. The learned graphs have no corporate-secrecy notion, so closing that needs a dedicated head or corpus retraining, which is a separate item.
- Gates: `tests/test_classifier.py` 63 passed and `tests/test_classifier_evals.py` 14 passed; full `pytest` 621 passed / 2 `model_integration` skips; ruff check and format clean; mypy clean (66 files); pylint 10.00/10; `check_adrs.py`, `validate_tool_catalog.py --check`, `validate_rbac.py`, `recalculate_dread.py --check` and `check_backlog.py --check` all OK.
