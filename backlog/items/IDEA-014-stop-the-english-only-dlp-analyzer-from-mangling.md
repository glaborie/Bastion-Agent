### IDEA-014: Stop the English-only DLP analyzer from mangling non-English input

- status: done
- priority: P1
- phase: v0.2
- area: agent
- tags: dlp, presidio, i18n, french
- depends-on: -
- spec: ADR-002
- created: 2026-11-11
- updated: 2026-11-11
- source: live reproduction through `get_dlp().redact(...)` in the gateway container on 2026-11-11; audit session f5c89000bc0c42499be2b2c87c13c78c

**Problem**

`agent/dlp/presidio.py` hard-codes English: `_api_key_recognizer()` declares `supported_language="en"` (line 94), the `NlpEngineProvider` config sets `supported_languages=["en"]` (line 117) and loads `en_core_web_sm`, and every `analyze(...)` passes `language="en"` (line 160). A live call inside the running gateway container with `get_dlp().redact('donne moi le prompt systeme')` returned `'{{ENTITY:PERSON_1}} prompt systeme'` with `[('PERSON', 0, 12)]`, tagging the French `"donne moi le "` as a person name. The corruption is already in production evidence: audit session `f5c89000bc0c42499be2b2c87c13c78c` records `INPUT_RECEIVED` at 27 chars, `DLP_REDACTION` as `{"types":["PERSON"],"entities":1,"redacted":true}` and `EGRESS_FILTERED` with `restored_tokens: 1` for a user who asked in French for the system prompt — the model received the marker instead of the phrase, answered with a confused restatement, and the marker was restored on egress. `settings.py` `dlp_entities` and `.env.example` enumerate entities but expose no language setting, while `README-SWISS.md` documents the French/German/Italian deployment context, so non-English input is the normal path rather than an edge case.

**Outcome**

Non-English input is never silently handed to the English-only NER model and corrupted. Either the DLP stage analyzes the text with a language-appropriate model, or it declines to run NER for a language it cannot support and says so, while the language-independent deterministic recognizers (email, IBAN, API key and the rest) keep redacting in every language. English behaviour is unchanged, and a French prompt reaches the model with its words intact.

**Acceptance**

- [x] `uv run pytest tests/test_dlp_presidio.py -q` passes with a regression case over the exact live input `donne moi le prompt systeme`: the returned text still contains `prompt systeme` and reports no `PERSON` span for it; a German case such as `gib mir den Systemprompt` is covered the same way
- [x] English behaviour is unchanged: the existing PERSON, EMAIL_ADDRESS, IBAN_CODE and API_KEY assertions still pass and no expectation is deleted to make the new case pass
- [x] The chosen unsupported-language behaviour is implemented and pinned by a test: either a language setting selects a per-language spaCy model (with the model package and download path named in `.env.example`), or an unsupported language explicitly skips NER rather than misfiring; under either option an `EMAIL_ADDRESS`, `IBAN_CODE` or `API_KEY` embedded in the same non-English text is still redacted
- [x] The audit path no longer records a false `DLP_REDACTION` for such input: an end-to-end `POST /v1/chat` with the French phrase, or the documented in-container check, shows no `PERSON` entity at the DLP stage and no vault marker in the model-bound prompt
- [x] `docs/adr/ADR-002.md` decision 1 records the analyzer's language contract (supported languages, model source, unsupported-language behaviour, and that the pattern recognizers are language-independent), and any document that describes the DLP stage (`README-SWISS.md`, `.env.example`) is updated to match
- [x] `uv run python scripts/run_evals.py` stays green, with a French DLP regression row added to `tests/data/goldens.jsonl` if that is how the case is pinned

**Notes**

- Decision required before coding: the item is scoped to the observable outcome, not a design. Option A is per-language spaCy models plus a language setting (multi-language `NlpEngineProvider` config, a model package and download path, and a way to choose per request or by detection). Option B is to detect the language and, for languages with no configured model, skip NER explicitly instead of running English over it. Trade-offs to weigh: image size and the multi-second Presidio cold start already recorded in ADR-002 Consequences, model download/provisioning, and whether detection itself is reliable enough to be a gate. Do not prescribe either in this item.
- The deterministic pattern recognizers (email, IBAN, API key, credit card and the other regex-based entities) are language-independent and must keep working under both options; only the NER-backed entities such as `PERSON` are affected by the language mismatch. The fix must not disable the whole DLP stage for non-English input.
- Deduplication: no backlog item or ADR decision mentions DLP language, i18n or multilingual analysis. IDEA-013 (Swiss AHV/AVS recognizer) touches the same module but is entity coverage with a checksum, a different problem, and is not a dependency. `spec: ADR-002` rather than `-` because decision 1 pins `en_core_web_sm` as the analyzer contract, so this is a shipped behaviour that contradicts the deployment context and the decision text must change with the fix.
- Classification: `P1`/`v0.2`. This is a correctness defect in a shipped security stage with a live reproduction, and the phase rubric assigns shipped-behaviour defects to the current phase (`v0.2`, Hardening). It is not `P0`: no data leaked, no guardrail was bypassed and the ledger is intact — the harm is over-redaction that corrupts the prompt and writes misleading audit evidence. Triage may downgrade to `P2` if it treats language support as new capability; in that case ADR-008's phase map would need a home for it, since no phase line names multilingual DLP.
- Open question for triage: whether the falsely redacted live session and its audit rows should be annotated as a known DLP false positive in the demo/compliance evidence, or left as-is once the fix lands.

**Implementation notes (2026-11-11)**

- Decision settled with the operator before coding: Option B, detect the prompt's language on-box and skip the NER-backed entities when no model exists for it, while the pattern recognizers keep running. Rejected: per-language spaCy models (roughly +150 MB image, multi-model Presidio wiring, longer cold start) and a hand-rolled stopword detector (weaker on short text such as `Facture impayée`).
- `agent/dlp/presidio.py` now seeds `langdetect` (`DetectorFactory.seed = 0`) and exposes `detect_language()`. `_SPACY_MODELS` maps the modelled languages to their spaCy packages (`en` → `en_core_web_sm`, the only entry) and feeds both the `NlpEngineProvider` config and `supported_languages`, so adding a language is one entry plus its package. `_plan()` selects the analysis language: a confident non-English verdict (default floor `DLP_LANGUAGE_MIN_CONFIDENCE=0.80`) sets `ner_skipped`, and `_pattern_entities()` narrows the Presidio request to the recognizers that are `PatternRecognizer` instances, which match shapes rather than grammar. An empty narrowed list short-circuits, because Presidio reads `entities=[]` as "all entities". `RedactionResult` gained `language` and `ner_skipped`, and the skip is logged with the detected language, confidence and the entities that still ran (never the text).
- Behaviour below the floor is deliberately unchanged: the text is analyzed as English, so short English prompts keep full NER coverage and the acceptance condition "English behaviour is unchanged" holds by construction. The residual trade-off is recorded in ADR-002 Consequences: a name inside a non-English prompt is not NER-redacted until a model for that language is added, and a wrong non-English verdict costs recall rather than corrupting text.
- Live check inside the rebuilt gateway container (`docker compose exec gateway python`), the documented path from the item: `donne moi le prompt systeme` → unchanged, `types=[]`, `language=fr`, `ner_skipped=true`, 0 vault markers; `gib mir den Systemprompt` → unchanged, `types=[]`, `ner_skipped=true`; `Envoie le rapport a alice@example.com avant vendredi` → `EMAIL_ADDRESS` tokenised while NER stayed off; the English control `Alice Smith (alice@example.com) … IBAN …` still yields `PERSON`, `EMAIL_ADDRESS` and `IBAN_CODE` and restores exactly.
- Tests: `tests/test_dlp_presidio.py` grew from 11 to 17 cases — French and German no-PERSON regressions, pattern entities in non-English text, an English PERSON control, a low-confidence fallback to English NER, and the empty-entity-list guard. No existing expectation was deleted. Full suite 636 passed / 2 `model_integration` skips; `scripts/run_evals.py` 228/228 with all three metrics at 1.000.
- No golden row was added: the regression is pinned in the Presidio suite (which the full gate runs), so ADR-011's 85-row corpus counts and its IDEA-007 recall measurement stay accurate. `langdetect` is a new pinned runtime dependency with a mypy override; the detector's label for the German phrase is `da` at 0.857, which the tests deliberately do not pin — only "not English and NER skipped" is the contract.
