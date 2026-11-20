### IDEA-098: Specify the intent-router contract in ADR-004

- status: inbox
- priority: P2
- phase: v0.6
- area: agent
- tags: routing, intent, orchestration, adr
- depends-on: -
- spec: ADR-004
- created: 2026-11-20
- updated: 2026-11-20
- source: intent-router description supplied on 2026-11-20, alongside IDEA-091

**Problem**

IDEA-091 captures intent *detection* — a keyword, lightweight-LLM and deep-LLM cascade behind a
confidence gate — but nothing records what the router around it must do. ADR-004 governs
complexity-to-model-tier selection and says nothing about classification before routing, deterministic
dispatch, compound utterances, fan-out and serialisation, arbitration, risk-tiered thresholds, ambiguity,
fallback, retries, conversation state, agent scoring, request-level policy or audit. Each of those would
otherwise be invented at implementation time, and two implementers would invent different rules for the
same word ("escalate" already means operator handoff in ADR-022 and classifier retry in IDEA-091).

**Requirements**

A well-designed intent router must:

1. **Classify before routing** — emit a structured intent label (or set) with a calibrated confidence
   score, never a free-form guess.
2. **Separate responsibilities** — keep the routing decision in deterministic workflow logic, not inside
   the model's prompt.
3. **Cascade cost tiers** — resolve easy requests with rules or a local/small model first, escalating to
   stronger models only when needed.
4. **Handle multi-intent utterances** — split or parse compound requests into discrete intents before
   dispatch.
5. **Fan out independent intents in parallel** to specialised agents with their own narrow roles and tools.
6. **Serialise dependent intents** when one step's output is another's input, respecting causal ordering.
7. **Answer simple queries locally** without invoking downstream agents or expensive models.
8. **Fuse multiple confidence signals** (model score, rule hits, similarity, history) into one calibrated
   gate rather than trusting self-reported confidence.
9. **Apply risk-tiered thresholds** — higher bars for irreversible or high-stakes actions than for
   read-only ones.
10. **Detect ambiguity explicitly** — when top candidates are close, ask a targeted clarification question
    instead of picking arbitrarily.
11. **Provide a fallback path** — a general-purpose agent or human handoff catches anything unclassifiable;
    nothing is silently dropped.
12. **Bound retries** — allow one or two reclassification attempts with a hard limit, then stop and
    escalate.
13. **Escalate on complexity or failure**, routing to stronger models or humans when automation cannot
    safely proceed.
14. **Track conversation state** — recognise continuations, feedback and mid-task shifts so the same words
    can route differently by context.
15. **Score agents on capability** (skill, domain, load, language), not just intent match, when several
    could serve.
16. **Arbitrate parallel outputs** — judge (pick best) or synthesise (fuse) when fanning out to multiple
    candidates.
17. **Resolve rule contention deterministically** — explicit priority or first-match-wins ordering so
    overlapping rules behave predictably.
18. **Apply request-level policy** — tenant, time or header conditions that vary routing without
    redeployment.
19. **Make every decision auditable** — log the intent, confidence, threshold applied, path taken and
    abstention status.
20. **Be honest about uncertainty** — prefer asking, escalating or abstaining over confidently misrouting,
    because containment of error matters more than the appearance of competence.

**Outcome**

ADR-004 is amended or superseded so these twenty properties are normative decisions rather than a
description in a backlog item. Each decision names the mechanism that satisfies it or states plainly that
it is not built yet, names the deterministic ordering rule for rule contention (17) and arbitration (16),
and fixes the vocabulary so "escalate", "fallback" and "abstain" have one meaning each across ADR-004,
ADR-022 and IDEA-091. No code changes in this item: the deliverable is the record, and IDEA-091 then
implements against it instead of the prose above.

**Acceptance**

- [ ] ADR-004 (amended or superseding) states all twenty properties as numbered decisions, each with the mechanism or an explicit "not built", and no property is dropped or merged silently
- [ ] The record fixes the contention order (17), the arbitration between parallel results (16) and the three terms "escalate", "fallback" and "abstain", reconciling ADR-022's operator handoff
- [ ] The record separates what exists today (`agent/routing/`, ADR-022 escalation, the golden corpus) from what is new, so triage can size the implementation without re-reading the code
- [ ] `uv run python scripts/check_adrs.py`, `uv run python scripts/check_backlog.py --check` and `scripts/gate.sh` pass, and IDEA-091's plan is checked against the record in that item's own change

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `intent`, `cascade`, `ambiguity`,
  `fan-out`, `arbitration`, `abstain`, `clarification`. IDEA-091 is the detection cascade (child of this
  contract, not a duplicate); IDEA-028 is complexity-to-tier routing; IDEA-018/IDEA-070 and ADR-022 own
  operator handoff; IDEA-073 is a request retry budget, not a reclassification budget; IDEA-036/060 are
  handler shape and the compat facade. No item or ADR records properties 2, 4-6, 8-12 and 14-19.
- `P2`/`v0.6`: nothing is broken today, and ADR-008 freezes new features inside v0.5. `agent` because the
  deliverable lands in `docs/adr/` governing `agent/routing/`; `docs` is the fair alternative if triage
  reads it as a writing task, rejected because the ADR is a decision record with ordering rules, not prose.
- Open questions for triage: whether this supersedes ADR-004 or appends a contract section to it (the
  current ADR is one decision about tiers, and twenty more may not belong in one file); whether 20 becomes
  a THREAT_MODEL control row if abstention is treated as a containment property; and whether property 9
  needs an irreversible-action taxonomy before the ADR can name thresholds at all.
