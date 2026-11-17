### IDEA-070: Detect paraphrased frustration, not just lexicon phrases

- status: ready
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

Two live conversations show the miss. Conversation
`1eb8182972004380b4808b4cb7cab123` (2026-11-17 14:52:31, 14:52:51, 14:55:31;
26/64/100 characters) and conversation `f41974de-e976-43cc-9a5f-d6ca512a3ed9`
(2026-11-17 16:49:46, 16:50:20, 16:50:42; 26/76/125 characters) each produced three
complete lifecycle rows, a `PUBLIC` route and **no `HANDOFF_REQUIRED` row** —
audit ids 831-845 and 902-916. In both cases the operator concluded frustration
"was detected" because the model answered apologetically; nothing in the system
agreed, the panel stayed empty and no notification fired (IDEA-069).

The second transcript was recovered through the escrow enabled for debugging
and is unambiguous to a human:

```
1  "this button is not working"
2  "no but seriously it's definitely not working, ever"
3  "I'm not sure you understand how frustrated I feel"
```

`assess` returns `None` because **no turn contains a marker**: `"not working"` is
not in the lexicon (only `"still not working"`, `"not working again"`,
`"doesn't work"`, `"does not work"`, `"nothing works"`), and `"frustrated"` is not
either (the list has `"fed up"`, `"i'm furious"`, `"this is ridiculous"`). The
repetition arm does not save it: the turns are restatements, not copies, with
Jaccard similarity 0.17 and 0.06 against the 0.9 threshold.

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

- [ ] The live miss is reproduced as a test: the `f41974de…` transcript (quoted above, committed as a fixture) yields a verdict after the change, and a neutral three-turn transcript of the same length yields none; the `1eb81829…` conversation must also fire once its wording is known
- [ ] A committed labelled set exists (at least 20 positive and 20 negative transcripts, English, with the real phrasings an operator sees) and the measured recall and false-positive rate are quoted in the ADR and in the item Notes; the thresholds are chosen from that table
- [ ] The overlapping-marker defect is fixed or explicitly documented: `"still does not work"` no longer counts as two markers, and a test pins the count for a phrase that contains another
- [ ] Tool output still cannot create a handoff (`<untrusted_content>` case from IDEA-018 stays green), the stage still makes no network or model call unless the ADR records a local-model decision, and DLP/route/canary/egress behaviour is unchanged
- [ ] ADR-022 decision 2 and its Consequences are amended with the new rule's measured limits, and `README.md`'s "Frustration handoff" section matches
- [ ] `scripts/gate.sh` is green, and the existing `tests/test_sentiment.py` expectations are updated only where the new rule intentionally changes them

**Notes**

- Live evidence: audit ids 831-845 (three `INPUT_RECEIVED` at 14:52:31, 14:52:51, 14:55:31 with 26/64/100 characters), no `HANDOFF_REQUIRED` between 14:50 and 14:57; the last handoffs before that are rows 752 (13:30) and 763 (13:47).
- The `f41974de…` transcript came out of `payload_escrow` through `POST /api/audit/{id}/escrow` as the dedicated `admin` account (rows 902, 907 and 912, readable until ~16:49 UTC on 2026-11-18). Escrow is on for the moment, so a future miss can be read the same way instead of guessed at; `1eb81829…` stays unknown because it predates the switch.
- The cheapest candidate, to be measured rather than assumed: add `"not working"`, `"frustrated"` and `"frustrating"` to the lexicon. That makes this conversation yield two distinct markers on turn 3 and fire, and it also makes an ordinary "why is X not working?" fire — a precision cost the labelled set has to price. If that price is too high, the rule needs a normalised negative-verb pattern instead of another literal phrase.
- The turns in the recovered example also show why the repeat arm (0.9 Jaccard) is the wrong shape: a frustrated person elaborates ("no but seriously…", "I'm not sure you understand…"), and the shared core ("not working") is a small fraction of each turn's vocabulary.
- The current rule is `len(markers) >= 2 or (markers and repeated)` with a 0.9 Jaccard threshold on word sets (`agent/sentiment.py`); the repeat arm also misses a restated complaint with one new sentence, which the labelled set should cover.
- This is the recall twin of IDEA-066 (the injection guard refusing "say OK"): both are calibration problems on a local model/rule pair, and both should be measured against a corpus rather than patched with a special case.
- Out of scope: sentiment-driven routing or model selection (ADR-022 decision 1 forbids acting on the turn), multilingual lexicons beyond English unless the ADR buys them, and any live human chat channel.
