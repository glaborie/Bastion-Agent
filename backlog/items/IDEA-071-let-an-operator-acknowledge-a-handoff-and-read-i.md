### IDEA-071: Let an operator acknowledge a handoff and read its transcript

- status: ready
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

- [ ] `POST`/`PATCH` acknowledge endpoint exists under `require_roles("operator", "admin")`, is tenant-scoped, records actor id and timestamp, is idempotent (a second call is a no-op that does not duplicate the record), and the panel renders the acknowledged state
- [ ] The decision on how acknowledgement is recorded is in the ADR — a new `HANDOFF_ACKNOWLEDGED` member under the ADR-007 decision 7 exception, or metadata on `HANDOFF_REQUIRED` with the append-only and hash-chain consequences spelled out; either way the chain still verifies
- [ ] Transcript view: shown only when a `payload_escrow` row exists for the conversation's `INPUT_RECEIVED` and/or `RESPONSE_SENT` record, read through the existing admin escrow path with its `ESCROW_ACCESSED` audit row, rendered as text (never HTML), and the plaintext is not written to the ledger, the trace or logs
- [ ] With escrow off or expired the panel says the transcript is unavailable and offers no control, asserted by a test with no escrow row
- [ ] Role tests: `readonly` and `analyst` cannot acknowledge (403) and cannot read a transcript even when their session is valid; `admin` in a different tenant cannot either (tenant scoping)
- [ ] `scripts/gate.sh` is green, `check_adrs.py` passes, and README's handoff section documents acknowledge and the escrow dependency

**Notes**

- Live evidence: row 854 (`HANDOFF_REQUIRED`, `24709be1-b652-46d1-a0c9-30baad1b10e0`, `escalating_language`); escrow verified on the same stack by decrypting rows 857/861 through `db.escrow.read_payload_escrow`, so the data path exists even though no acme admin can read it over HTTP.
- The tenant/role gap is real and worth deciding with this item: escrow read is `admin`-only and tenant-scoped, and the seeded realm has `breakglass` (admin, `platform`), `alice`/`bob` (`acme` operator/analyst) and `carol` (`globex` analyst). Either an acme admin is granted (realm change) or the acknowledge action stays operator-visible while the transcript requires an admin from the same tenant.
- Acknowledge is not "resolved": with no live channel (ADR-022 decision 6) there is nothing to close, so the item deliberately stops at "someone owns this now" and leaves resolution/assignment out.
- Out of scope: SLA timers, assignment to a named operator, notifying the caller, editing or replying to the conversation, and any transcript retention beyond the escrow TTL.
