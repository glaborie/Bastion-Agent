### IDEA-017: PII that Presidio fails to detect reaches cloud-primary in plaintext

- status: done
- priority: P1
- phase: v0.2
- area: security
- tags: dlp, presidio, pii, classifier, routing
- depends-on: -
- spec: ADR-002
- created: 2026-11-11
- updated: 2026-11-11
- source: live incident through POST /v1/chat on 2026-11-11, conversation 8eb86a76d79e413bbb9f2d5cd3bf9ad9, OTel trace 38c9f47edabca937c78c999862080b74, audit rows 530-533

**Problem**

On 2026-11-11 a live `POST /v1/chat` through the real gateway (conversation
`8eb86a76d79e413bbb9f2d5cd3bf9ad9`, OTel trace
`38c9f47edabca937c78c999862080b74` — three spans: `POST /v1/chat` 21.9 s,
`chat cloud-primary` 3.4 s, `POST /v1/chat/completions` 3.4 s; audit rows 530-533
in `audit_logs`) sent one prospect record to OpenAI. The prompt was a name
`Senapus Perillard`, street `Piazza Indipendenza 102`, city `6808 Torricella`,
country `Switzerland`, phone `091 479 98 31`, email
`SenapusPerillard@teleworm.us` and `Born April 7, 1996`. `DLP_REDACTION`
recorded `{"types":["EMAIL_ADDRESS","PHONE_NUMBER"],"entities":2,"redacted":true}`
— only the phone and the email were tokenised. `ROUTING_DECISION` recorded
`{"label":"PUBLIC","local":false,"model":"safety-guard","route":"cloud-primary","reason":"public_content","confidence":0.9233}`
and `EGRESS_FILTERED` recorded
`{"model":"openai/gpt-4o-mini","route":"cloud-primary","restored_tokens":2}`. So
the name, the postal address and the date of birth were sent to `gpt-4o-mini` in
plaintext, the assistant echoed them back, and the egress filter restored the two
tokens for the authorised client exactly as designed.

Reproduced directly against `get_analyzer()` on 2026-11-11: `"Senapus
Perillard"` returns `[]` — `en_core_web_sm` tags no PERSON at all, even at
`score_threshold` 0.0 — while `"Alice Smith"`, `"Maria Keller"` and `"Müller
Beat"` are tagged PERSON 0.85, so the miss is name-shaped (out-of-vocabulary
surname), not a wiring bug. The full record at threshold 0.0 yields
`EMAIL_ADDRESS` 1.0, `LOCATION` 0.85 (only `Switzerland`; the street and city are
not parsed), `DATE_TIME` 0.85 (`April 7, 1996` plus a spurious `98 31` inside the
phone number), `PHONE_NUMBER` 0.75 and `URL` 0.5 (`teleworm.us`). `LOCATION` and
`DATE_TIME` are absent from the default `DLP_ENTITIES` in `settings.py`
(`PERSON,EMAIL_ADDRESS,PHONE_NUMBER,IBAN_CODE,IP_ADDRESS,CREDIT_CARD,US_SSN,API_KEY`),
so even the spans Presidio does find are dropped, and there is no address
recognizer at all. The language gate is not the cause: `detect_language()` read
the record as `it` at 0.571, below `DLP_LANGUAGE_MIN_CONFIDENCE` 0.80, so NER
still ran.

The root cause is two independent gaps that compose. (a) DLP recall is a fixed
entity list plus one English spaCy model, and it misses an unusual personal name
plus every entity type outside that list. (b) The two-model classifier has no
personal-data notion at all — the `sensitive_personal` rule is a keyword list
(`passport`, `social security`, `bank account`, `medical record`, `diagnos*`),
and the ensemble knows corporate confidentiality, injection and safety — so
`PUBLIC` is a correct answer to the question it is asked, and nothing forces
PII-bearing text to `local-llama` when redaction is incomplete. The golden corpus
encodes the second gap: PII rows carry `expected_label: null`.

**Outcome**

A prompt that is a structured personal record no longer reaches a cloud route
with an unredacted name, postal address or date of birth: it is either kept on
`local-llama`, refused, or sent only after every field the record contains has
been tokenised. Whichever route is chosen is recorded as a decision in ADR-002,
the ledger says why on the request's own rows, and the corpus and tests pin the
record so the behaviour cannot regress. No existing redaction, routing, canary
or four-eyes behaviour is weakened to achieve it.

**Acceptance**

- [x] `uv run pytest tests/test_dlp_presidio.py tests/test_classifier.py -q` passes with a regression case built from the recorded prompt (name, street, city, country, phone, email, date of birth) asserting the chosen outcome, and no existing assertion is deleted or loosened to make it pass
- [x] The regression fails on the current tree: the same case reports `EMAIL_ADDRESS` and `PHONE_NUMBER` only, `PUBLIC`, `cloud-primary`, or sends the name, street/city or date of birth untokenised — the failing-before evidence is captured in the item's implementation notes
- [x] `tests/data/goldens.jsonl` gains at least one row built from the recorded prompt whose `expected_label`/`expected_route` states the chosen outcome (or the PII rows' `expected_label: null` is filled), no existing row or assertion is removed, and `uv run python scripts/run_evals.py` stays green
- [x] A live `POST /v1/chat` with the recorded prompt shows the outcome on the server span and in `audit_logs`: `route=local-llama`, or a refusal, or `cloud-primary` with `DLP_REDACTION` naming every field of the record; no `EGRESS_FILTERED` row restores tokens from a completion that echoes an untokenised name, postal address or date of birth
- [x] `docs/adr/ADR-002.md` records the chosen option — decision 1 (DLP entity/list contract) and, if routing or a refusal is chosen, decision 2 (routing contract) — including the honest boundary that recall is a fixed entity list plus one English NER model, and `uv run python scripts/check_adrs.py` passes
- [x] `uv run pytest -q` (full suite), `ruff check .`, `ruff format --check .`, `mypy`, `pylint`, `uv run python scripts/check_backlog.py --check`, `check_adrs.py`, `validate_tool_catalog.py --check`, `validate_rbac.py` and `recalculate_dread.py --check` all still pass
- [x] No document claims DLP redacts all PII: every README/THREAT_MODEL/SECURITY sentence that describes the DLP stage names the entity-list boundary or links the ADR decision

**Notes**

- Decision needed, not chosen here. Three options, and they are not exclusive: (i) route any prompt that looks like a structured personal record, or where DLP found PII but coverage is incomplete, to `local-llama`; (ii) fail closed with `503` when a prompt looks like a structured personal record; (iii) close the gap by entity coverage alone — address and date-of-birth recognizers, a broader NER model. Option (iii) cannot catch an out-of-vocabulary name, which is the miss in this incident, so if it is taken it likely needs (i) or (ii) as a backstop. The operator decides; the ADR records it.
- The record above is the one audit row 530 captured. It is reproduced because the miss is name- and shape-specific and cannot be restated generically; it is the incident's captured prospect data, not a live customer record taken from elsewhere.
- Deduplication: IDEA-013 (Swiss AHV/AVS recognizer) edits the same `dlp_entities` contract but is one missing identifier type with a checksum, not recall of names, addresses or dates of birth; IDEA-014 (done) changed the language contract and is explicitly not the cause here (verdict 0.571 is below the 0.80 floor, so NER ran); IDEA-015 is semantic disclosure at egress; IDEA-016 is payload escrow that would make the next such incident debuggable. No backlog item and no ADR decision mentions structured personal records, address recognizers or a PII routing gate. `spec: ADR-002` rather than `-` because decision 1 fixes both the entity list and the analyzer contract that produced the miss, so the fix edits a governing decision.
- Classification: `P1`/`v0.3`, per triage direction. The rubric's `P0` case ("breaks a stated security invariant: leak") is arguable — ADR-002's Context says "Real PII must never leave the gateway boundary" — but the shipped control behaved as its own decision specifies, so this is a coverage defect in the specification rather than a bypass; raise it to `P0` if the operator treats any unredacted PII at a cloud provider as phase-blocking. `v0.3` is the conservative home for post-v0.2 security work: the phase rubric would put a shipped-behaviour defect in the current phase (`v0.2`), no ADR-008 v0.2 line names PII recall, and the nearest named work is v0.6 "custom DLP adapters". Triage may pull it into v0.2.
- Scope is one decision plus its proof. Deliberately out: a general recognizer catalog, per-country address formats, retraining the classifier with a personal-data head, and any change to the vault or egress token-restore behaviour. Those become their own items if the chosen option needs them.
- Open question for triage: whether the incident's audit rows 530-533 should be annotated as a known DLP recall gap in the demo/compliance evidence, or left as-is once the fix lands.
- Intake only. No code, ADR, corpus, config or test change is part of this capture.
