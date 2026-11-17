### IDEA-066: Calibrate the injection guard for short benign prompts

- status: inbox
- priority: P2
- phase: v0.4
- area: agent
- tags: classifier, injection, calibration, evals
- depends-on: -
- spec: ADR-011
- created: 2026-11-17
- updated: 2026-11-17
- source: session report on 2026-11-17 ("say OK is blocked as prompt injection")

**Problem**

A two-word benign prompt is refused as a prompt-injection attempt. Repeating the
same request against the running stack (audit rows 786-790, 791-795 and the
`sentiment` check that produced them) gives:

```
"say OK"        -> blocked, CONFIDENTIAL, reason prompt_injection_detected, confidence 0.9197
"hello"         -> PUBLIC, 0.9963
"thanks"        -> PUBLIC, 0.9968
"what time is it" -> PUBLIC, 0.9970
```

The guard is `_OnnxInjectionModel.predict` (`agent/routing/classifier.py:405`),
which takes `max` of `_softmax(window)[1]` over the token windows, and
`decide_ensemble` treats `injection_prob >= thresholds.injection` (0.662 in the
`production` profile, 0.5 in `recall-first`, ADR-011 decision 3) as a detection.
A two-token prompt has almost no context for a 268 MB guard trained on
conversational attacks, and the max-over-windows rule removes the dilution a
mean would give. The consequence is worse than a wrong route: per ADR-012
decision 10 the chat gateway refuses the turn before inference, so the caller
gets the injection notice and no answer at all, and the refusal is indistinguishable
from a real attack in the ledger (`prompt_injection_detected`, confidence 0.9197).

Nothing in the corpus pins this: `tests/data/goldens.jsonl` has 19
injection-related rows, all of them realistic attack and benign sentences, and
none shorter than a few words. Raising the threshold is not a fix — 0.9197 is far
above 0.662 and the same 0.662 catches the true positives the guard exists for.

**Outcome**

A short benign turn ("say OK", "yes please", "do it") is answered normally while
the guard keeps every true positive the corpus and the eval gates already hold.
The fix is measured before it is chosen: the injection score of a short-prompt
set is recorded per prompt length, one calibration approach is selected and
recorded as a decision (ADR-011 amendment or a superseding ADR), and the change
ships with the corpus rows that pin it. Rejected by default: raising the global
threshold, special-casing the literal string, and disabling the guard for short
text without a measured reason — each weakens a control to hide a symptom.

**Acceptance**

- [ ] The measurement exists in the change: injection probabilities for a short-prompt set (2-6 tokens, at least ten prompts including "say OK") at the active profile, quoted in the item Notes or the ADR, so the chosen cut is evidence-based and not a guess
- [ ] The chosen approach is recorded in ADR-011 (amended or superseded) with its effect on the production and `recall-first` operating points, and states explicitly what it does not cover (e.g. a two-word attack that stays below the new cut)
- [ ] A regression test fails before the change and passes after: "say OK" through the classifier (and through `POST /v1/chat`) is `PUBLIC` and answered, while at least one short attack string that the guard did catch still returns `prompt_injection_detected`
- [ ] `tests/data/goldens.jsonl` grows with the short benign and short attack cases, and `scripts/run_evals.py` stays at its zero-tolerance result for injection recall
- [ ] `scripts/gate.sh` is green, including `scripts/run_evals.py` (`--evals`), and no existing injection test expectation is relaxed

**Notes**

- Evidence: `GET /api/audit?conversation_id`-style lookup on audit ids 786-790 (`perf-check-3`, "say OK", `blocked=true`, `block_reason=prompt_injection_detected`) and 806-810, 811-815, 816-820, 821-825 for the four-prompt sweep at 14:32 UTC; the same stack answered "hello", "thanks" and "what time is it".
- The failure mode is not new to this session: the guard is evaluated first and cannot be overridden (ADR-011 decision 3), so a false positive is a hard refusal, not a routing hint. That is the right direction for a real attack and the reason this calibration has to be measured rather than guessed.
- Open questions for whoever takes it: whether the model expects sub-word padding or a minimum window that short prompts do not fill; whether `max` over windows should become a length-aware reduction; whether a separate short-prompt operating point belongs in `EnsembleThresholds`; and whether the caller should see a distinct reason (e.g. `injection_short_prompt`) instead of the same notice a real attack produces.
- Out of scope: the safety guard's categories, DLP, and any change to the streaming/refusal UX.
