### IDEA-013: Add a Presidio recognizer for Swiss AHV/AVS numbers

- status: done
- priority: P2
- phase: v0.2
- area: agent
- tags: presidio, dlp, pii, swiss
- depends-on: -
- spec: ADR-002
- created: 2026-11-10
- updated: 2026-11-10
- source: THREAT_MODEL.md T4 residual risk and tests/data/goldens.jsonl row pii-social-security-009, 2026-11-10

**Problem**

The deterministic DLP stage has no recognizer for the Swiss AHV/AVS number. The default entity list in `settings.py` (`dlp_entities`, line 113) and `.env.example` line 127 names eight entities, and `get_analyzer()` in `agent/dlp/presidio.py` registers exactly one custom recognizer, `_api_key_recognizer()` (line 119), so a number such as `756.1234.5678.90` is never replaced with a vault marker. The gap is already recorded rather than guessed: `THREAT_MODEL.md` T4 says "The default entity list has no Swiss-specific identifiers (for example the AHV/AVS number). Add custom recognizers before a Swiss deployment." Routing may still keep such a prompt local through the classifier's `sensitive_personal` floor, but that is a confidentiality verdict, not redaction — the identifier enters the model context in plaintext, can be echoed back through the egress stage, and leaves no reversible marker for an authorised recipient. The corpus encodes the gap: row `pii-social-security-009` carries `expected_redactions: []` with the note "Presidio has no Swiss AHV recogniser; the sensitive_personal floor covers it", so the DLP metric never asserts this class. `README-SWISS.md` line 70 presents the entity list as the Swiss-market answer without qualifying it.

**Outcome**

An AHV/AVS number is detected as its own entity type, replaced with a stable `{{ENTITY:...}}` vault marker like any other PII, and restored only for its own session. The recognizer is checksum-aware so the 13-digit format is not confused with arbitrary numbers, the default entity list ships with it, and every document that enumerates the DLP entity set names it.

**Acceptance**

- [x] `uv run pytest tests/test_dlp_presidio.py tests/test_dlp_evals.py -q` passes with a new case: checksum-valid `756.1234.5678.90` is redacted as `AHV_NUMBER` and appears in `result.entity_types`, while the same digits with a wrong check digit are not redacted
- [x] `agent/dlp/presidio.py` registers the recognizer beside `_api_key_recognizer()`, the regex and the EAN-13 check-digit rule are named in a module comment, and a dotted, a space-separated and a bare 13-digit spelling are covered by tests
- [x] `settings.py` `dlp_entities` default and `.env.example` line 127 include the new entity, and a deployment that pins `DLP_ENTITIES` in `.env` still starts and still redacts only the entities it names
- [x] `tests/data/goldens.jsonl` row `pii-social-security-009` gains `expected_redactions: ["AHV_NUMBER"]` with no existing assertion removed, and `uv run python scripts/run_evals.py` stays green
- [x] `docs/adr/ADR-002.md` decision 1 names the recognizer, its pattern, checksum rule and score, `THREAT_MODEL.md` T4 drops the "no Swiss-specific identifiers" residual risk, and `README-SWISS.md` line 70 lists the added entity

**Notes**

- Deduplication: `BACKLOG.md` had no item mentioning recognizers, entity coverage, PII, Presidio or Swiss identifiers before this capture; the only Swiss hits were prose about the market. `THREAT_MODEL.md` T4 and golden row `pii-social-security-009` both document the gap as residual risk, not as planned work, and no ADR decision implements it. `spec: ADR-002` is right rather than `-` because decision 1 of the DLP ADR fixes the entity set, so widening it edits a governing decision ("covered by an ADR but not built") and the item includes that edit.
- Classification: `P2`/`v0.3` because this is new capability and ADR-008 decision 5 freezes features inside a phase. No ADR-008 phase bullet names Swiss identifiers; the nearest is v0.6 "custom DLP adapters", and v0.3 is the phase that already touches Presidio. Triage may move it to v0.6 if recognizers are treated as the adapter work, or pull it into v0.2 if the Swiss-market reference architecture is judged part of the current definition of done.
- Scope is one recognizer. Deliberately out: the Swiss UID/CHE company number, postal account numbers and other country identifiers; those shape "recognizer catalog" work rather than this item. Also out: migrating `DLP_ENTITIES` to a versioned catalog, and any change to the classifier floor that currently routes such prompts.
- Open questions for triage: whether the entity type should be `AHV_NUMBER` (the name used above) or a Swiss-prefixed form such as `CH_AHV`; and whether the recognizer's pattern score should sit above `DLP_SCORE_THRESHOLD` (0.35) unconditionally or below it unless the checksum validates, since a 13-digit identifier that is only format-matching risks over-redacting order and account references.
- Acceptance assumes the checksum rule is part of the recognizer; if Presidio's `PatternRecognizer` cannot express it, the implementation needs a small custom `EntityRecognizer` subclass, which is a larger change than the pattern-only recognizers shipped today and should be decided before coding.

**Implementation notes (2026-11-11)**

- Decisions taken with the operator: accept a number only when the EAN-13 check digit holds (rejecting the item's own example, which is invalid), and name the entity `AHV_NUMBER`. Rejected: format-only matching (over-redacts every `756…` 13-digit reference) and requiring an AHV context word for the bare form (departs from the acceptance criterion and depends on the context enhancer).
- **The item's example was wrong.** `756.1234.5678.90` fails the EAN-13 check; the valid digit is `7`, so the canonical value is `756.1234.5678.97`. The golden row and every test use the valid number, and `tests/test_dlp_presidio.py` pins the invalid one as *not* redacted. The row's prompt was corrected in place, so the corpus stays at 86 rows and ADR-011's counts are unchanged.
- **Implementation.** `agent/dlp/presidio.py` gains `_AHV_PATTERN` (dotted, space-grouped and bare spellings behind `(?<!\d)`/`(?!\d)` boundaries), `_ahv_check_digit`/`_is_valid_ahv` (EAN-13, weights 1,3 over the twelve payload digits) and `_ahv_recognizer()`. The recognizer is a `PatternRecognizer` subclass overriding Presidio's `validate_result` hook: a `False` drops the match and a `True` promotes its score, so the pattern's 0.85 base becomes 1.0 on a valid number. Staying a `PatternRecognizer` matters: IDEA-014's non-English path (`_pattern_entities`) keeps only pattern recognizers, so a custom `EntityRecognizer` would have silently stopped redacting AHV in French/German prompts. The class is defined inside the factory, not at module level, so importing the module still does not import Presidio and a missing install remains a `DLPUnavailableError` at analyzer init rather than an ImportError.
- **Configuration.** `settings.py`, `.env.example` and `docker-compose.yml` all list `AHV_NUMBER`. The compose default matters: `tests/test_settings.py::test_compose_dlp_entity_default_matches_settings` now covers the new entity too, which is the drift IDEA-017 hit live.
- **Measured residual, recorded not hidden:** `756` is Switzerland's GS1 prefix, so a Swiss EAN-13 product barcode is checksum-valid and is redacted as an AHV. ADR-002 decision 1 and THREAT_MODEL T4 state the collision; THREAT_MODEL's "no Swiss-specific identifiers" residual is replaced by it, and the still-missing UID/CHE and postal-account numbers are named.
- **Tests.** `tests/test_dlp_presidio.py` grows 21 → 28: valid dotted number redacted and restored, all three spellings detected, three invalid check digits ignored, no match inside a longer number, redaction with the NER pass skipped (French), and a deployment that pins `DLP_ENTITIES` to `EMAIL_ADDRESS` still leaving the AHV untouched while redacting the address.
- **Live check** in the rebuilt gateway (`docker compose up -d --force-recreate gateway worker`): dotted → `AHV_NUMBER` and `{{ENTITY:AHV_NUMBER_1}}`, space-grouped → token, bare → token, `756.1234.5678.90` → no entity and text unchanged, French `numero AVS …` → token with `ner_skipped=true`; every case restored exactly for its own session.
- Gates: `scripts/gate.sh --integration --evals` → 11/11, pytest 657 passed / 2 model-integration skips, evals 232/232 (the golden row now contributes a DLP eval case) with all metrics 1.000, pylint 10.00/10, mypy clean.
