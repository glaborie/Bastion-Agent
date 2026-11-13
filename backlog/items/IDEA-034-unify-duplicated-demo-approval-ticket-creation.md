### IDEA-034: Unify duplicated demo approval-ticket creation

- status: inbox
- priority: P2
- phase: v0.3
- area: agent
- tags: approvals, duplication, four-eyes, demo
- depends-on: -
- spec: ADR-010
- created: 2026-11-12
- updated: 2026-11-12
- source: review of `agent/demo/scenarios.py` and `scripts/seed_demo_approval.py`, 2026-11-12

**Problem**

Two demo paths each hand-build a `PendingApproval`. `_run_seed_approval` (`agent/demo/scenarios.py:402-458`) computes the TTL with `PendingApproval.expiry_for(now, settings.approval_ttl_seconds)` at line 411, the fingerprint at 419, the HMAC capability token at 420-425, the row at 428-441, the `APPROVAL_REQUESTED` audit event at 443-451 and the Redis publish at 452-458; `create_ticket` (`scripts/seed_demo_approval.py:40-94`) repeats the same sequence at lines 51, 53, 54-59, 63-76, 78-86 and 87-93. Both sit outside the guarded suspension in `agent/tools/execution.py::_suspend` (lines 526-593), which is the only construction site that a change to the fingerprint, the token expiry or the audit fields is normally tested against. The demo audit rows already differ from `_suspend`'s: the demo payload is `{"ticket_id", "tool"}` with `{"required_role"}` metadata, while `_suspend` also records `request_fingerprint`, `initiator_id`, `expires_at` and `argument_keys`. Nothing makes those three sites drift together, so a security-relevant field can change in one demo path and not the other.

**Outcome**

One factory builds the demo ticket — TTL, fingerprint, capability token, token hash, row insert, `APPROVAL_REQUESTED` audit event and Redis publish — and both demo callers use it, so a later change to the suspension contract reaches them in one edit. Observable behaviour is unchanged: the same ticket fields, the same audit event and the same publish, and `_suspend` remains the guarded path rather than being folded into the demo helper.

**Acceptance**

- [ ] `grep -rn "PendingApproval" agent/demo/scenarios.py scripts/seed_demo_approval.py` returns nothing, and the ticket row, the token and the audit event are readable at one shared factory call site
- [ ] A test calls the factory and asserts the row's fields from `settings.approval_ttl_seconds` (expiry), `fingerprint_request(tool, arguments)` (fingerprint), `hash_approval_token` of a token that `sign_approval_token` verifies, and the `APPROVAL_REQUESTED` payload and metadata that both demo paths publish today
- [ ] `uv run pytest tests/test_dashboard_demo.py tests/test_approvals.py -q` passes with no assertion deleted, and the dashboard seed scenario still yields a pending ticket whose initiator cannot approve it
- [ ] Nothing in `agent/tools/execution.py` changes: `_suspend` keeps its own construction and its audit fields, and the four-eyes behaviour for worker-suspended tickets is untouched

**Notes**

- Deduplication: grepped `BACKLOG.md`, `docs/adr/` and the tree for `PendingApproval`, `seed_demo_approval`, `_suspend` and `four-eyes`. IDEA-012 (done) built the demo console and its seed scenario, and its notes call the scenario "the dashboard equivalent of `scripts/seed_demo_approval.py`", which is the duplication this item removes rather than a second feature. IDEA-002 (done) is approval transport, IDEA-030 (done) is worker identity, IDEA-021 is ledger retention; no item or ADR records the duplicated construction.
- `spec: ADR-010` because decision 4 owns the immutable request binding — fingerprint, HMAC token, token hash — and decision 8 owns the `APPROVAL_REQUESTED` fields; the factory must not weaken either. The ADR text needs no change unless the factory's audit fields are deliberately aligned with `_suspend`'s fuller set, in which case decision 8 records it.
- Open question for triage: whether the shared factory also becomes `_suspend`'s constructor. This item deliberately does not, because moving the guarded path is a larger security change than de-duplicating two demo helpers, and the drift it would fix is the same one this factory makes visible.
- Classification: `P2`/`v0.3`. No guardrail is broken today (the demo rows are valid and four-eyes is enforced downstream), so it is not `P0`/`P1`; the current phase is v0.3 and this is a duplicate-removal refactor with no new capability.
