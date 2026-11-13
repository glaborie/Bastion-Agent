### IDEA-037: Replace the classifier's 24-keyword constructor with a guard configuration object

- status: inbox
- priority: P3
- phase: v0.3
- area: agent
- tags: classifier, config, refactor, onnx
- depends-on: -
- spec: ADR-011
- created: 2026-11-12
- updated: 2026-11-12
- source: review of `agent/routing/classifier.py` on 2026-11-12

**Problem**

`SensitivityClassifier.__init__` (`agent/routing/classifier.py:438-561`) is 124 lines with 24 keyword-only parameters. The injection-guard and safety-guard settings are mirror images — model path, tokenizer path, max tokens, CPU SHA-256, GPU path and GPU digest each exist twice — and `_graph_for_provider`, `_operating_unsafe_threshold`, `_validate_operating_points` and the two guard constructions are interleaved in one body, so reading the CUDA operating-point selection requires tracking locals across 40 lines. `get_classifier()` (`:895-921`) passes 21 of those settings values one by one, and four scripts plus two test modules call the constructor directly, so any signature change is a wide, error-prone edit.

**Outcome**

The constructor takes one frozen configuration object plus the two optional predictors and nothing else. That object holds the paths, digests, token and threshold values for both guards, the rules-floor flag and the require-models flag; a single `_build_guard` helper resolves the provider graph and constructs either an injection guard or a safety guard, so the constructor validates the config and builds the two guards instead of mixing selection, validation and loading. `get_classifier()` builds the config from settings. Behaviour, error messages and fail-closed semantics are unchanged, including the paired-guard rule and the `require_models` check.

**Acceptance**

- [ ] `SensitivityClassifier.__init__` takes at most 6 parameters excluding `self` (the config object, `injection_predictor`, `safety_predictor`, and any keyword-only validation switches that remain), asserted by a test using `inspect.signature` so the count cannot drift back
- [ ] `uv run pytest tests/test_classifier.py tests/test_classifier_evals.py -q` passes after adapting only direct constructor calls; no assertion is deleted, loosened or skipped to make it pass
- [ ] The existing configuration-error assertions keep their message text: `model not found`, `tokenizer not found`, `threshold`, `max_tokens`, `configured together`, `no classifier model`
- [ ] Every direct call site is migrated (`tests/test_classifier.py`, `tests/test_classifier_evals.py`, `scripts/demo_classifier.py`, `scripts/tune_classifier.py`, `scripts/measure_classifier_latency.py`, `scripts/check_classifier_dispatch.py`), and `grep -rn "SensitivityClassifier(" --include=*.py agent tests scripts` shows no remaining argument-by-argument construction
- [ ] `uv run mypy agent/routing/classifier.py` and `uv run ruff check agent/routing/classifier.py scripts tests` pass
- [ ] A CUDA provider selection with no GPU graph configured still keeps the configured CPU graph and the configured `unsafe` default, proven by the existing GPU operating-point test

**Notes**

- Scope is simplification only: no new graph, threshold, recognizer or model feature; the rules floor, the ensemble decision table and the single-graph legacy path stay as they are.
- The item's premise said `get_classifier()` passes 22 values; counting the call at `agent/routing/classifier.py:899-921` gives 21 (`safety_unsafe_threshold` and both predictors are not passed), which does not change the conclusion.
- Open question for triage: whether the config object lives in `agent/routing/classifier.py` beside `EnsembleThresholds` or in a separate module; a second module is only worth it if the scripts need to build the config without importing the classifier.
- ADR-011 decision 6 already fixes the graph-paths-from-settings contract and the provider selection rules, so this refactor must read that decision rather than redefine it.
