### IDEA-050: Audit both approval expiry paths and mark the ticket decided

- status: inbox
- priority: P1
- phase: v0.3
- area: agent
- tags: audit, approvals, ledger
- depends-on: -
- spec: ADR-010
- created: 2026-11-13
- updated: 2026-11-13
- source: security review of feat/backlog-list on 2026-11-13

**Problem**

`expire_stale_approvals` (`agent/tools/execution.py:315-341`) and the lapsed-ticket branch of
`resume_approved_tool` (`:203-209`) set `EXPIRED` with no `append_audit_event`, and there is no
`APPROVAL_EXPIRED` member in `AuditEventType`. Neither sets `decided_at`, so
`list_recently_decided` (`gateway/approvals.py:188`) hides the ticket.

The ledger for an expired mutating request ends at `APPROVAL_REQUESTED`, indistinguishable from a
ticket still awaiting a decision, and no operator sees it again.

**Outcome**

Expiry is a terminal, audited transition that appears in the ledger and in the dashboard's decided
list.

**Acceptance**

- [ ] Both expiry paths append an `APPROVAL_EXPIRED` event and set `decided_at`
- [ ] A test forces a ticket past its expiry, runs the sweep, and asserts the ledger row
- [ ] The expired ticket appears in `list_recently_decided`
