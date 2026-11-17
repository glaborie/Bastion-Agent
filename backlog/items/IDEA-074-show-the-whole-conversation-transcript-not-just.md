### IDEA-074: Show the whole conversation transcript, not just the newest request and answer

- status: inbox
- priority: P2
- phase: v0.4
- area: gateway
- tags: dashboard, handoff, escrow, transcript
- depends-on: IDEA-071
- spec: ADR-022
- created: 2026-11-17
- updated: 2026-11-17
- source: session report on 2026-11-17 ("show transcript is not showing the full transcript")

**Problem**

The handoff panel's **Show transcript** renders the newest escrowed
`INPUT_RECEIVED` record plus the newest `RESPONSE_SENT` record, nothing more
(ADR-022 decision 9, `gateway/audit_service.py::handoff_transcript_records`).
That was the acceptance of IDEA-071 — "the conversation's newest escrowed
request and delivered answer" — but it is not what an operator reads as a
transcript.

Conversation `bcdad02e-0472-4a39-99fa-a07884ca63c1` shows the gap. The ledger has
three requests (1, 2 and 3 messages, rows 1132, 1137 and 1142) and three answers
(1136, 1141, 1147). The panel shows the third request's three user turns and the
third answer:

```
user: the button is not working
user: seriously, the button is not working again
user: it still doesn't work
assistant: It sounds frustrating that the button isn't working. …
```

The two earlier answers — the ones the caller was reacting to when they said
"seriously" and "it still doesn't work" — are missing, and the same three user
turns appear as one block instead of three turns in order. The reader cannot see
the exchange that produced the frustration, which is the whole reason the
transcript exists.

**Outcome**

**Show transcript** on a handoff renders the conversation as it happened —
every escrowed request and answer in ledger order, one turn per message, with
the role labelled — rather than the last request and last answer. The escrow
rule does not change: only an `admin` can read it, every decrypted record
appends its own `ESCROW_ACCESSED` row, an expired or missing entry is shown as
unavailable rather than failing the click, and no text reaches the ledger, a
trace or a log.

**Acceptance**

- [ ] `handoff_transcript_records` (or its replacement) returns **all** escrowed
  `INPUT_RECEIVED` and `RESPONSE_SENT` rows for the conversation in id order, and
  the panel renders them turn by turn — a three-turn conversation from
  `bcdad02e…` shows three user turns and three assistant turns, not one block
  and one answer
- [ ] The read stays admin-only and CSRF-guarded, one `ESCROW_ACCESSED` row per
  decrypted record, and the count is bounded (a documented cap, e.g. the newest
  50 turns) so one click cannot walk an unbounded ledger page
- [ ] A test seeds a multi-turn conversation with escrow on and asserts the
  order, the per-record audit rows and the cap; a conversation whose middle
  entry expired still renders the entries that are readable, with a note where
  one is not
- [ ] `docs/adr/ADR-022.md` decision 9 and `README.md`'s "Operator handoffs"
  paragraph state what the transcript now shows, and `scripts/gate.sh` is green

**Notes**

- The cap should be a settings key with a default, like `MAX_HANDOFF_RECORDS`,
  so an operator can widen it without a code change; each decrypt is an audit
  row, so the cap is also a bound on ledger noise.
- Escrow rows expire after 24 h, so an older conversation can legitimately have
  a request without its answer; that is the "unavailable" case the current
  fragment already renders for the whole conversation and should now render per
  turn.
- The rendering must stay inside the escaped `<pre>` (ADR-022 decision 9): the
  text is caller-authored and may contain markup.
- Not in scope: making the transcript available to `operator` (it decrypts
  escrow, so it stays admin-only), and any change to what the handoff queue
  itself shows a non-admin.
