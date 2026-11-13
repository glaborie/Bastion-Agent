### IDEA-046: Merge overlapping Presidio spans instead of dropping the longer one

- status: ready
- priority: P0
- phase: v0.3
- area: agent
- tags: dlp, presidio, pii
- depends-on: -
- spec: ADR-002
- created: 2026-11-13
- updated: 2026-11-13
- source: security review of feat/backlog-list on 2026-11-13

**Problem**

`agent/dlp/presidio.py:492-506` sorts results by `(start, -score, -end)` and keeps a span only if
`start >= last_end`. At equal start the higher-scoring span wins outright, so a longer overlapping
span is discarded and its uncovered tail stays in the prompt. The docstring says "keep the
highest-scoring, longest span", which the code does not do.

Verified against the function itself: `PERSON(15,43,0.85)` plus `ADDRESS(15,59,0.80)` keeps only
`PERSON` and leaves `' 12, 8001 Zurich'` uncovered. A name running straight into a street address
is the normal Swiss/German record shape, so house number, postcode and city reach the model while
the `DLP_REDACTION` row records `types: ["PERSON"]`.

**Outcome**

Every character of a detected entity is replaced, and the recorded types match what was removed.

**Acceptance**

- [ ] A test asserts `"8001" not in redact("Please ship to Alice Mueller Bahnhofstrasse 12, 8001 Zurich today").text`
- [ ] A test covers two overlapping spans with the same start and opposite score/length ordering
- [ ] The `_select_non_overlapping` docstring matches the behaviour
