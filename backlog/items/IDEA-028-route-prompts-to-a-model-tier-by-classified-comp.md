### IDEA-028: Route prompts to a model tier by classified complexity

- status: done
- priority: P2
- phase: v0.4
- area: agent
- tags: routing, classifier, cost, latency, omniroute
- depends-on: -
- spec: ADR-004
- created: 2026-11-12
- updated: 2026-11-17
- source: session request on 2026-11-12 ("add a prompt classifier to route to the appropriate model based on complexity")

**Problem**

`ModelRouter._decision` (`agent/routing/client.py:279-298`) has exactly two outcomes: a
`CONFIDENTIAL` verdict or a DLP hit goes to `local-llama`, and everything else goes to
`cloud-primary`, the only two aliases `settings.py:262-263` and
`config/omniroute/config.yaml` define. The classifier in `agent/routing/classifier.py`
measures sensitivity — secrecy, injection, harm — and never how much work a request is,
so a one-line lookup and a multi-step analysis both land on `openai/gpt-4o-mini`, and the
per-response `usage.cost` read into `ChatCompletion.cost_usd` is recorded and never acted
on. ADR-004's Context names "sensitivity, cost, and availability" as the routing inputs,
but decision 3 implements sensitivity alone, and the local GPU serves a single Qwen 7B, so
there is no second tier to choose from on either side.

**Outcome**

A request is routed to a model tier by a complexity verdict that is separate from, and
subordinate to, the sensitivity verdict: complexity may choose among models of the same
confidentiality class, never move a `CONFIDENTIAL` or `pii_detected` request off the local
path, and never route a prompt the DLP stage could not fully redact to a cloud model.
Simple traffic stops paying for the strongest alias, hard traffic keeps it, the verdict and
its evidence appear on the `ROUTING_DECISION` row and the server span, the aliases and
thresholds are settings keys, and ADR-004 decision 3 records the policy it does not
currently have.

**Acceptance**

- [x] `uv run pytest tests/test_routing_complexity.py -q` routes a fixture of simple and hard prompts to the configured cheap and strong aliases, and `tests/test_routing_client.py` plus `tests/test_classifier.py` pass with no existing assertion changed
- [x] Confidentiality wins in the same module: a `CONFIDENTIAL` prompt the complexity verdict calls simple still routes `local-llama`, and a `PUBLIC` prompt with `pii_detected` still routes `local-llama`, with neither verdict's label rewritten
- [x] The new aliases exist in `config/omniroute/config.yaml` and are restored by `scripts/omniroute_bootstrap.py`, their names and thresholds are settings keys documented in `.env.example`, and `docker compose config` is unchanged
- [x] The `ROUTING_DECISION` payload and the server span carry the complexity verdict, its score and the chosen alias without prompt text, and `docs/adr/ADR-014.md`'s attribute allow-list names any new attribute
- [x] `uv run python scripts/run_evals.py` stays green, and a recorded run over a named prompt set (the golden corpus or a documented sample) reports the tier distribution and median per-turn `usage.cost`, recorded in ADR-004
- [x] `docs/adr/ADR-004.md` decision 3 records the tier policy, the complexity signal, the default thresholds and the honest boundary that a misroute is a cost or quality regression and never a confidentiality one; `uv run python scripts/check_adrs.py` passes

**Notes**

- Deduplication: grepped `BACKLOG.md`, `docs/adr/` and the code for `complexity`, `complex`, `difficulty`, `simple`, `reasoning`, `tier` and `model selection`. IDEA-003 (done) is the classifier latency budget on GPU, IDEA-007 and IDEA-017 are sensitivity and PII routing correctness, and IDEA-018 explicitly lists "sentiment-driven routing or model selection" as out of scope for a different signal — none is complexity-based tiering. No ADR decision covers it: ADR-004 decision 2 fixes the two aliases and decision 3 fixes the sensitivity policy, so `spec: ADR-004` names the record that must change rather than a decision that already permits it.
- Classification: `P2`/`v0.4`/`agent`. New capability with nothing broken today — every turn is served, no invariant is crossed — so not `P0`/`P1`, and ADR-008 decision 5 freezes features inside a phase while the current phase is `v0.3`. No ADR-008 line names complexity routing; `v0.4` "adaptive policy" is the conservative next-phase home, while `v0.5` "token and cost budgets remain open" and `v0.6` "multi-provider OmniRoute, local model hot-swap" are the nearer textual homes if triage treats this as cost control or as routing-plane work. `area: agent` because the change is the routing decision in `agent/routing/`, with the OmniRoute combos and settings as thin surfaces.
- Decisions deliberately not taken: the complexity signal (a third head on the ONNX ensemble, prompt-length and step-count heuristics, or a model-reported difficulty), the number of tiers and which concrete models back them, whether the local tier gains a second smaller model or stays the confidential-only path, and whether a caller may request a tier at all — a caller override must not become a way to move a confidential prompt to the cloud.
- Ordering to weigh before coding: complexity has to be read from the same raw text the sensitivity classifier sees (`gateway/routers/chat.py:355` classifies the raw scan), so the verdict cannot be derived from redacted text without changing what routing sees; and cost budgets are still open in ADR-008 v0.5, so recording spend per tier may belong with them rather than here.
- Scope: intake only. No classifier, router, OmniRoute config, settings, `.env.example`, test, ADR or documentation edit is part of this capture.
- Implementation: `agent/routing/complexity.py` is a deterministic signal — named markers (`step_by_step`, `enumerated_items`, `multi_question`, `code_block`, `analysis_verb`, `trade_offs`, each counted once) weighted `0.7` plus a length ramp from 40 to 160 words weighted `0.3`, compared against `COMPLEXITY_THRESHOLD` (default `0.6`). `ModelRouter.route/aroute` read it from the same raw text the classifier reads and put it on `RouteDecision.complexity`; `_decision` uses it only when neither the label is `CONFIDENTIAL` nor `pii_detected` is set, and it never touches `override`, so the label and the override semantics of ADR-002 decision 5 are unchanged.
- Tier names: `cloud-strong` (`MODEL_CLOUD_STRONG_ALIAS`) is the new alias; `cloud-primary` (`MODEL_CLOUD_ALIAS`) stays the default for a `SIMPLE` PUBLIC prompt. The strong combo is the same two providers in the opposite priority (`claude-haiku-4.5` first), so tiering introduces no new provider or model id that this deployment has not already validated, and `tests/test_routing_complexity.py` pins both the alias→first-target mapping and the `config/omniroute/config.yaml` ↔ `scripts/omniroute_bootstrap.py` combo drift.
- Evidence: `ROUTING_DECISION` metadata gains `complexity` and `complexity_score` beside `route`; the server span gains `bastion.complexity` and `bastion.complexity.score`, both named in ADR-014 decision 3. Neither carries prompt text: `tests/test_chat.py::test_the_routing_row_reports_complexity_without_prompt_text` asserts the values and that no metadata or span value contains the prompt's phrase.
- Measured sample (recorded in ADR-004 decision 3): 9 prompts — the four `SIMPLE_PROMPTS` and four `COMPLEX_PROMPTS` fixtures plus a 200-word unmarked paste — routed through `ModelRouter` against the live OmniRoute and completed once each. Distribution 5 simple → `cloud-primary`, 4 complex → `cloud-strong`; per-turn `usage.cost` medians $0.00000936 (cheap) and $0.00129492 (strong), whole sample $0.00006059. The strong tier is ~138x the cheap tier per turn on this sample; the sample measures the cost of the split, not the quality gain.
- Live check on the rebuilt stack (gateway built from this branch): `tier-live-simple` → `cloud-primary`, complexity `simple`, score `0.0`; `tier-live-complex` → `cloud-strong`, complexity `complex`, score `0.7`; a complex prompt carrying an address stayed `local-llama` with complexity still recorded as `complex`, and a complex `CONFIDENTIAL` prompt stayed `local-llama`. `scripts/omniroute_bootstrap.py` created the `cloud-strong` combo on the live OmniRoute (201) and its smoke test answered from `anthropic/claude-haiku-4.5`.
- Not done on purpose: no second local model, no caller-requested tier, and no per-tier spend ledger — ADR-008 v0.5 still owns cost budgets, so this item only records the verdict and lets OmniRoute's `usage.cost` stay where it is.
