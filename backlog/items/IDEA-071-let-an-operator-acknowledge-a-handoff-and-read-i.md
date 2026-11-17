### IDEA-071: Let an operator acknowledge a handoff and read its transcript

- status: done
- priority: P2
- phase: v0.4
- area: gateway
- tags: handoff, dashboard, escrow, audit, hitl
- depends-on: IDEA-018, IDEA-065
- spec: ADR-022
- created: 2026-11-17
- updated: 2026-11-17
- source: session report on 2026-11-17 ("Alice can see the new handoff but she can't do anything about it")

**Problem**

A handoff is currently a row that cannot be acted on. `GET /api/handoffs/panel`
and the dashboard fragment show the conversation id, verdict and time, and the
only link goes to `/dashboard/sessions/{id}`, the generic audit timeline. There is
no acknowledge, no owner, no dismissal and no transcript: an operator learns that
someone is stuck and has nothing to do with it, so the queue silently grows and
"handled" is indistinguishable from "nobody looked". Reproduced on the running
stack: conversation `24709be1-b652-46d1-a0c9-30baad1b10e0` wrote
`HANDOFF_REQUIRED` (row 854, `escalating_language`), Alice saw it in the panel and
could only open the session page; there is no field or action anywhere that says
she saw it.

The transcript is recoverable in principle — with `PAYLOAD_ESCROW_ENABLED=true`
the raw input and the delivered answer are in `payload_escrow` for 24 h — but the
only read path is `POST /api/audit/{id}/escrow`, admin-only and one row at a time,
so an operator-driven workflow would mean opening the ledger and finding the
ids by hand. It is also not reachable today in the `acme` tenant at all, because
no seeded acme account holds `admin` (ADR-005 decision 7 keeps the read
tenant-scoped, correctly).

**Outcome**

An operator/admin can mark one handoff acknowledged (who, when), it stops
appearing as new, and the panel shows the state instead of a bare row; the same
view offers the conversation's transcript **when escrow permits it**, read through
the existing admin escrow path and never persisted again. Acknowledge is an
audit-visible action (its own event type if ADR-007 decision 7's vocabulary freeze
allows it, otherwise a metadata field on a permitted member, decided in the ADR),
idempotent, and tenant-scoped. When escrow is off or expired, the transcript
control is absent and the page says so rather than failing on click. Nothing here
creates a live chat channel or changes the caller's turn.

**Acceptance**

- [x] `POST`/`PATCH` acknowledge endpoint exists under `require_roles("operator", "admin")`, is tenant-scoped, records actor id and timestamp, is idempotent (a second call is a no-op that does not duplicate the record), and the panel renders the acknowledged state
- [x] The decision on how acknowledgement is recorded is in the ADR — a new `HANDOFF_ACKNOWLEDGED` member under the ADR-007 decision 7 exception, or metadata on `HANDOFF_REQUIRED` with the append-only and hash-chain consequences spelled out; either way the chain still verifies
- [x] Transcript view: shown only when a `payload_escrow` row exists for the conversation's `INPUT_RECEIVED` and/or `RESPONSE_SENT` record, read through the existing admin escrow path with its `ESCROW_ACCESSED` audit row, rendered as text (never HTML), and the plaintext is not written to the ledger, the trace or logs
- [x] With escrow off or expired the panel says the transcript is unavailable and offers no control, asserted by a test with no escrow row
- [x] Role tests: `readonly` and `analyst` cannot acknowledge (403) and cannot read a transcript even when their session is valid; `admin` in a different tenant cannot either (tenant scoping)
- [x] `scripts/gate.sh` is green, `check_adrs.py` passes, and README's handoff section documents acknowledge and the escrow dependency

**Notes**

- Implementation: `POST /api/handoffs/{conversation_id}/acknowledge` (operator/admin, CSRF on a session, tenant-scoped) appends one `HANDOFF_ACKNOWLEDGED` row and re-renders the panel; `POST /api/handoffs/{conversation_id}/transcript` (admin, CSRF) reads the newest escrowed `INPUT_RECEIVED` and `RESPONSE_SENT` rows through `read_payload_escrow`, appends one `ESCROW_ACCESSED` per read, and renders the turns in an auto-escaped `<pre>`. The panel offers the transcript control only when `payload_escrow` still holds the request row, and shows "transcript unavailable (escrow off or expired)" otherwise; an operator never sees that control because the read is admin-only (ADR-005 decision 7).
- Recording decision: a new `HANDOFF_ACKNOWLEDGED` ledger member, because the ledger is append-only and a flag on the handoff row would be a mutable record. ADR-022 decision 9 records it, ADR-007 decision 7's exception paragraph names it, and `AUDIT_EVENT_VOCABULARY_DDL` widens the CHECK constraint by looking for the new member so an existing database is upgraded on boot. One acknowledgement per conversation; a second call is a no-op.
- Tests: `tests/test_dashboard.py` +4 (acknowledge once and idempotent with actor/verdict metadata; analyst/readonly 403 and a cross-tenant admin 404 with no row; transcript 403 for operator/analyst/readonly and the unavailable message without escrow; transcript reads escrow and writes exactly two `ESCROW_ACCESSED` rows while the text never lands in them) and `tests/test_handoffs_panel.py` +3 (acknowledge form, acknowledged badge with short actor hash, admin-only transcript control and the unavailable note). The JSON queue now carries `acknowledged`/`acknowledged_at`, and the existing key-set assertion was updated.
- Live verification on the rebuilt stack: acknowledging `e486c4a8-e40c-4e82-af22-6b3d560ca592` returned 200 and exactly one row, a second call returned 200 with the count still one, `/api/handoffs` showed `acknowledged: true` with a timestamp, the admin transcript returned the conversation's "still not working" turns, and the same transcript call as an operator returned 403. A conversation with no handoff row returned 404, which is why the first live attempt against `f41974de…` failed: that conversation was never flagged (IDEA-070), it only has escrow rows.
- `scripts/gate.sh` 13/13; `check_adrs.py` OK with 23 ADRs; DB-backed `tests/test_dashboard.py` 32 passed against a throwaway PostgreSQL.
