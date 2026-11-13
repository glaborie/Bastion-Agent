### IDEA-053: Scope /api/audit/verify to the caller's tenant and bound its limit

- status: inbox
- priority: P2
- phase: v0.3
- area: gateway
- tags: audit, tenancy, dos
- depends-on: -
- spec: ADR-015
- created: 2026-11-13
- updated: 2026-11-13
- source: security review of feat/backlog-list on 2026-11-13

**Problem**

`verify_audit_chain` (`db/audit.py:163`) scans the ledger globally and the route
(`gateway/routers/audit.py:114`) accepts `limit` up to 1,000,000, returning the global `checked`
count and a global `first_bad_id` (`:127-132`). The chain is global by design, so the global scan
is intended; the disclosure and the materialisation are not.

An `operator` of one tenant can bisect `limit` to read every tenant's audit volume, learn global
record ids, and force up to 10^6 ORM rows per request (60/min per the dashboard bucket), denying
service to the shared gateway process.

**Outcome**

The response exposes only what the caller's tenant may see, and one request cannot materialise
more than a bounded number of rows.

**Acceptance**

- [ ] `limit` is capped at a documented maximum below the ledger size
- [ ] `checked` and `first_bad_id` are tenant-scoped, or replaced by a per-tenant view
- [ ] A test shows an operator of tenant A cannot learn the global record count
