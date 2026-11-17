### IDEA-070: Detect paraphrased frustration, not just lexicon phrases

- status: inbox
- priority: P2
- phase: v0.4
- area: agent
- tags: sentiment, handoff, lexicon, recall
- depends-on: -
- spec: ADR-022
- created: 2026-11-17
- updated: 2026-11-17
- source: session report on 2026-11-17 ("rob's frustration was detected I guess" — the ledger shows it was not)

**Problem**

`agent/sentiment.py::assess` only knows a fixed list of literal phrases and a
consecutive near-identical repeat, so ordinary complaint language records
nothing. Reproduced against the deployed module:

```
"the export is still broken" + "this is useless"   -> fires (escalating_language)
"it is broken again" + "nothing helps here"        -> silent
"i already told you twice"                         -> silent
"that did not help"                                -> silent
```

Conversation `1eb8182972004380b4808b4cb7cab123` is the live case: three turns at
14:52:31, 14:52:51 and 14:55:31 (26, 64 and 100 characters cumulative), each with
`DLP_REDACTION`, a `PUBLIC` route and `RESPONSE_SENT`, and **no
`HANDOFF_REQUIRED` row** — audit ids 831-845. The operator concluded frustration
"was detected" because the model answered apologetically; nothing in the system
agreed, the panel stayed empty and no notification fired (IDEA-069). The text is
not recoverable — `INPUT_RECEIVED` stores a digest and escrow is off — so this
item starts by asking for the transcript, not by guessing at it.

There is also a counting defect in the same rule: `"still does not work"` matches
both `"still does not work"` and `"does not work"`, so one sentence yields
`markers == 2` and fires alone, while the docstring promises two *distinct*
markers or one marker plus repetition. Today's rule is simultaneously too literal
(misses paraphrase) and too loose on overlap (double-counts one phrase).

**Outcome**

A realistic complaint phrased without the exact listed words is detected, the
marker count reflects distinct evidence rather than overlapping substrings, and
the turn's other stages are untouched. The change is measured, not asserted: a
labelled set of complaint and neutral transcripts is committed, recall and
precision on it are recorded in the ADR, and the rule that ships is the one the
numbers support — whether that is a widened lexicon, a normalised match, a
paraphrase-tolerant heuristic, or a small local model is decided by that
measurement and recorded in ADR-022 (amended) before the code lands.

**Acceptance**

- [ ] The live miss is reproduced as a test: the transcript from `1eb81829…` (supplied by the reporter, since the ledger cannot return it) yields a verdict after the change, and a neutral transcript of the same length and turn count yields none
- [ ] A committed labelled set exists (at least 20 positive and 20 negative transcripts, English, with the real phrasings an operator sees) and the measured recall and false-positive rate are quoted in the ADR and in the item Notes; the thresholds are chosen from that table
- [ ] The overlapping-marker defect is fixed or explicitly documented: `"still does not work"` no longer counts as two markers, and a test pins the count for a phrase that contains another
- [ ] Tool output still cannot create a handoff (`<untrusted_content>` case from IDEA-018 stays green), the stage still makes no network or model call unless the ADR records a local-model decision, and DLP/route/canary/egress behaviour is unchanged
- [ ] ADR-022 decision 2 and its Consequences are amended with the new rule's measured limits, and `README.md`'s "Frustration handoff" section matches
- [ ] `scripts/gate.sh` is green, and the existing `tests/test_sentiment.py` expectations are updated only where the new rule intentionally changes them

**Notes**

- Live evidence: audit ids 831-845 (three `INPUT_RECEIVED` at 14:52:31, 14:52:51, 14:55:31 with 26/64/100 characters), no `HANDOFF_REQUIRED` between 14:50 and 14:57; the last handoffs before that are rows 752 (13:30) and 763 (13:47).
- Ask the reporter for the three messages before choosing an approach: without them the item can only widen the lexicon blindly, and the acceptance criteria deliberately require the real transcript.
- The current rule is `len(markers) >= 2 or (markers and repeated)` with a 0.9 Jaccard threshold on word sets (`agent/sentiment.py`); the repeat arm also misses a restated complaint with one new sentence, which the labelled set should cover.
- This is the recall twin of IDEA-066 (the injection guard refusing "say OK"): both are calibration problems on a local model/rule pair, and both should be measured against a corpus rather than patched with a special case.
- Out of scope: sentiment-driven routing or model selection (ADR-022 decision 1 forbids acting on the turn), multilingual lexicons beyond English unless the ADR buys them, and any live human chat channel.
