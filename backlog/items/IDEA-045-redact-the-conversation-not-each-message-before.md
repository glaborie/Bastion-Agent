### IDEA-045: Redact the conversation, not each message, before the PII routing decision

- status: inbox
- priority: P0
- phase: v0.3
- area: agent
- tags: dlp, presidio, pii, routing
- depends-on: -
- spec: ADR-002
- created: 2026-11-13
- updated: 2026-11-13
- source: security review of feat/backlog-list on 2026-11-13

**Problem**

`gateway/routers/chat.py:262-272` runs `dlp.redact` once per turn; `entity_count` at `:342`
drives `pii_detected` at `:383`, which is what keeps a prompt on the local model
(`agent/routing/client.py:290`). An identifier split across two adjacent turns matches nothing in
either turn: `"Please pay CH93 0076 2011"` and `"6238 5295 7 by Friday."`. The classifier's IBAN
floor does not bridge them either, because the scan text joins turns with `"\n\n"`
(`chat.py:378`) and the pattern needs contiguous groups.

Result: `entity_count == 0`, no rule marker, `PUBLIC`, cloud alias, and the cloud receives the
complete IBAN in plaintext. The `DLP_REDACTION` row records `entities: 0`, so the ledger asserts
the turn was clean.

**Outcome**

An identifier split across adjacent turns is either tokenised or counted, so a prompt containing
it routes local and the ledger records the entities found.

**Acceptance**

- [ ] A test posts two turns whose concatenation is a valid IBAN (and one with an email) and asserts the route is local
- [ ] The ledger row for that turn records the entity types that were found
- [ ] ADR-002 states the redaction unit (conversation, not message) and the test proves it
