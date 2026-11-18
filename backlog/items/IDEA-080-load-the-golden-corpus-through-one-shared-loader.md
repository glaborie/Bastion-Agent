### IDEA-080: Load the golden corpus through one shared loader

- status: inbox
- priority: P2
- phase: v0.5
- area: evals
- tags: goldens, evals, classifier, refactor
- depends-on: -
- spec: ADR-006
- created: 2026-11-18
- updated: 2026-11-18
- source: refactoring scan of the golden-corpus readers, 2026-11-18

**Problem**

Three readers parse `tests/data/goldens.jsonl` independently: `tests/goldens.py`
(a ten-field `Golden` dataclass plus `load_goldens`), `scripts/tune_classifier.py`
(its own five-field `Golden` dataclass and loader, which requires
`expected_label` and ignores `expected_route`, `expected_reason`,
`expected_redactions`, `expected_score` and `notes`) and
`scripts/benchmark_classifier_goldens.py` (`load_prompts`, which reduces each row
to a bare `prompt` string). The tuner picks the classifier thresholds that the
eval gate then asserts over the same rows, so a field one parser reads and
another ignores is a correctness seam: a row the gate asserts on gets tuned as
if the field did not exist, and a corpus edit that drops `expected_label` stops
the tuner while the gate reads it as `None`. ADR-006 decision 1 fixes the row
contract in one place, so the code should read it in one place too.

**Outcome**

`tests/goldens.py` is the single home for the corpus contract: one `Golden`
dataclass, one `load_goldens`, and the exported `GOLDENS_PATH`.
`scripts/tune_classifier.py` and `scripts/benchmark_classifier_goldens.py` import
that dataclass and loader instead of declaring their own, the benchmark's
`--goldens` default becomes `GOLDENS_PATH`, `tests/data/goldens.jsonl` stays
byte-identical, and no golden case changes verdict — for every existing row both
scripts read the same field values they do today.

**Acceptance**

- [ ] `uv run pytest tests/test_classifier.py tests/test_classifier_evals.py tests/test_dlp_evals.py tests/test_egress_evals.py -q` passes
- [ ] `uv run python scripts/tune_classifier.py --json` and `uv run python scripts/benchmark_classifier_goldens.py --json` report the same corpus row count as before the change on a host with the ensemble configured
- [ ] `grep -rn "class Golden" --include='*.py' tests scripts` prints exactly one line (`tests/goldens.py`), and `grep -n "json.loads" scripts/tune_classifier.py scripts/benchmark_classifier_goldens.py` prints nothing
- [ ] `uv run mypy tests/goldens.py scripts/tune_classifier.py scripts/benchmark_classifier_goldens.py` is clean under the repo's strict config
- [ ] `git diff --exit-code tests/data/goldens.jsonl` succeeds (corpus unchanged)

**Notes**

- Deduplication: no existing item owns this. IDEA-008 (done) is the
  CI dispatch-reproducibility verdict, not corpus parsing; IDEA-037 migrated the
  `SensitivityClassifier(...)` constructor call sites in these two scripts but
  left their loaders alone; IDEA-013, IDEA-017, IDEA-018 and IDEA-066 add corpus
  rows. No ADR decides a loader location, so this is new work, not a restatement.
- `spec: ADR-006` rather than ADR-011: decision 1 of ADR-006 fixes the corpus
  path and the row field contract, which is what is being unified. ADR-011 owns
  the threshold calibration and the `known_gap` verdicts and merely consumes the
  corpus, so it is the consumer, not the governing decision. Open question for
  the human: if a future calibration needs tuner-only fields, they are added to
  the shared dataclass deliberately, which is the point of the change.
- Proposed location is the existing `tests/goldens.py`, not a new
  `agent/evals/` package: the corpus is a test fixture, `tests` is already an
  importable package used by three eval suites, and both scripts already depend
  on the repo layout (`tests/data/...` defaults, and the GPU recipe mounts
  `tests/` into the image). Promote it to a shipped module if a non-test
  consumer ever needs it, not before.
- One behaviour change, confined to malformed input: the shared loader raises
  `ValueError` where the two scripts raised `SystemExit`. Each script should
  convert it at its own boundary to keep its CLI exit code; no golden case
  verdict changes.
- Priority/phase confirmed against the rubric: P2/v0.5 — a real correctness
  seam that is not part of a phase definition of done and can wait one phase.
