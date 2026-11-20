### IDEA-091: Detect intent through keyword, lightweight-LLM and deep-LLM layers with confidence-gated decisions

- status: inbox
- priority: P2
- phase: v0.6
- area: agent
- tags: routing, intent, classifier, confidence, calibration
- depends-on: -
- spec: ADR-004
- created: 2026-11-20
- updated: 2026-11-20
- source: session request on 2026-11-20 ("implement intent detection and separation ... L1 code layer ... L2 Lightweight LLM ... L3 Deep LLM ... confidence gated routing with Accept, Retry, Fallback, Escalate")

**Problem**

Every turn is treated as the same kind of request. `ModelRouter._decision`
(`agent/routing/client.py:464`) maps a sensitivity label plus the complexity tier
to one of three aliases (`local-llama`, `cloud-primary`, `cloud-strong`) and never
records *what the caller wants*; `agent/routing/classifier.py` measures secrecy,
injection and harm, not intent. `gateway/routers/chat.py` therefore has one path
for a lookup, a tool request and a multi-step task, so any later dispatch (tool
selection, specialist prompt, refusal shape) has no intent signal to act on. There
is also no cheap-to-expensive escalation: the classifier has one confidence
threshold (`CLASSIFIER_CONFIDENCE_THRESHOLD`, default 0.55) and one fallthrough
(treat as `PUBLIC`), so an ambiguous prompt is not re-read by a stronger layer and
nothing in the tree produces an explicit Accept/Retry/Fallback/Escalate decision
with a calibrated confidence behind it. ADR-004 decision 3 names sensitivity and
complexity as routing inputs and stops there.

**Outcome**

An intent is detected in three layers of increasing cost: L1 deterministic
keyword/regex matching that resolves unambiguous prompts with no model call; L2 a
lightweight local LLM for prompts L1 cannot separate; L3 a deep LLM (the strong
alias) only when L2's confidence is below its threshold. A single calibrated
confidence gate then chooses one of four decisions — Accept (use the verdict),
Retry (re-read, at most a bounded number of attempts), Fallback (use a declared
safe default intent) and Escalate (send to the next layer or to the existing
operator handoff) — with every layer, verdict, confidence and decision recorded on
the `ROUTING_DECISION` row and the server span, without prompt text. The verdict is
subordinate to sensitivity exactly as complexity is: no intent decision may move a
`CONFIDENTIAL` or `pii_detected` prompt off `local-llama`, and L2/L3 inference for
such a prompt uses local only. Thresholds, per-layer timeouts and the attempt
bound are settings keys documented in `.env.example`, and an ADR records the
cascade contract and its measured calibration.

**Acceptance**

- [ ] `uv run pytest tests/test_intent_router.py -q` proves a fixture of unambiguous prompts resolves at L1 with zero model calls, and an ambiguous fixture climbs L1→L2→L3 with the layer recorded per turn; the L3 call is asserted not to happen when L2 clears its threshold
- [ ] The four decisions are a pure function of the calibrated score, each boundary has a test, and one labelled fixture makes every decision reachable together with its recorded layer
- [ ] `tests/test_routing_client.py` no-cloud-fallback and PII fail-closed assertions pass unchanged, and a test shows an intent verdict cannot move a `CONFIDENTIAL` or `pii_detected` prompt off `local-llama` (L2/L3 for those prompts run local only)
- [ ] The `ROUTING_DECISION` payload and the server span carry intent label, layer, confidence, decision and attempt count without prompt text, and `docs/adr/ADR-014.md`'s attribute allow-list names every new attribute
- [ ] A calibration run over a documented labelled intent set reports per-decision precision/recall and the measured layer distribution, the thresholds and timeouts are settings keys documented in `.env.example`, and the run is recorded in the ADR
- [ ] The ADR that records the L1/L2/L3 contract, the four decisions and the escalation meaning (amending ADR-004 or adding a new ADR) passes `uv run python scripts/check_adrs.py`, and `scripts/gate.sh` is green

**Notes**

- Deduplication: IDEA-028 (done) is complexity→model-tier routing — it never classifies intent and has no layered cascade or four-way decision; IDEA-018/070 are frustration detection and the operator handoff queue, which is the only existing use of "escalate" (ADR-022); IDEA-073 is the request deadline/retry budget for a model call, not a confidence-gated classifier retry; IDEA-036 splits the chat handler, IDEA-060 is the OpenAI-compatible facade. Grepping `backlog/items/`, `docs/adr/` and `HANDOVER_SPEC.md` for `intent`, `cascade`, `ambiguous` and `confidence-gated` finds no matching item and no ADR decision; `Intent` appears only as English prose. No item is amended, so this is a new item rather than a merge.
- Classification: `P2`/`v0.6`/`agent`. New capability with nothing broken today, so not `P0`/`P1`; ADR-008 decision 5 freezes features inside a phase, `backlog/config.toml` puts the current phase at `v0.5`, and no ADR-008 line names intent detection, so `v0.6` (the next open slot, "future-proofing") is the conservative home while `v0.4` "adaptive policy" is the nearest textual relative if triage reads the cascade as adaptive routing. `area: agent` because the work sits beside `agent/routing/classifier.py`, `complexity.py` and `client.py`; `spec: ADR-004` names the record that governs the routing policy and must be amended or superseded, not a decision that already permits it.
- Open question for triage — the word "separation": it can mean labelling one dominant intent per turn, or splitting a compound request ("book it and email me the receipt") into several intents. This capture assumes a single label plus a flag when the prompt carries more than one, because splitting a request changes the turn contract (`ChatRequest`/`ChatTurn`) and the audit shape; triage must pick before acceptance 2 is coded.
- Open question for triage — "Escalate": this item means escalating to the next layer or out of the automatic path. If the fourth decision can reach a person, it must reuse the existing `HANDOFF_REQUIRED` vocabulary and queue (ADR-022) rather than invent a second meaning of "escalate" in the ledger.
- Open questions deliberately not decided: the intent taxonomy and who owns it (fixed enum versus tool-derived), whether L2 is the local Qwen model (which shares the single scarce GPU with `local-llama` completions) or a smaller distilled ONNX head, the L2/L3 confidence thresholds and attempt bound, and whether the verdict feeds tool selection, prompt selection or both. Launching a second model per ambiguous turn spends the same GPU the confidential path depends on, so the per-layer timeout and concurrency budget need a measurement before the defaults are fixed.
- Companion capture: the request says an intent router *description* will be captured as a separate item. That item has no id at capture time, so `depends-on` stays `-`; if it lands first and this item is unbuildable without it, add the id to `depends-on` at triage instead of guessing one here.
- Scope: intake only. No router, classifier, settings, `.env.example`, test, ADR or documentation file was changed, and no layer was prototyped.
