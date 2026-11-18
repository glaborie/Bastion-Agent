### IDEA-075: Show the caller's tenant in the dashboard header

- status: active
- priority: P3
- phase: v0.4
- area: gateway
- tags: dashboard, multi-tenancy, ux
- depends-on: -
- spec: -
- created: 2026-11-18
- updated: 2026-11-18
- source: session on 2026-11-18 (a handoff written under `platform` was invisible to acme operators, with no UI cue about the active tenant)

**Problem**

The operator bar renders the caller's display name and roles and nothing else
(`gateway/dashboard/templates/base.html:45-50`), while every read on the page is
filtered by `AuthContext.tenant_id` (`gateway/dashboard/routes.py`). An operator
on a shared browser, or anyone reading a screenshot after an incident, cannot
tell which tenant scope the page is showing, so a row queued in another tenant
is indistinguishable from one that never existed — the confusion behind the
2026-11-18 report that a notification fired but neither acme operator could see
the handoff. `Principal.tenant_id` (`gateway/auth/oidc.py:112`) is already in
every dashboard template context, so this needs no query, claim or migration.

**Outcome**

Every dashboard page names the caller's tenant scope next to the principal and
roles, rendered from `principal.tenant_id` with the template's normal
auto-escaping and no additional request or data fetch. The label is the same
scope the page is filtered by, so it cannot disagree with the queue, the ledger
or the session inspector.

**Acceptance**

- [ ] `tests/test_dashboard.py` asserts the operator bar on `/dashboard` and `/dashboard/audit` names the session's tenant (`acme`), and that a session for a second tenant shows that tenant and not `acme`
- [ ] `scripts/gate.sh` is green

**Notes**

- Undecided and deliberately left open: whether the header shows the opaque `tenant_id` or something human-readable. No tenant display name exists in the tree — the token carries only the scope (`tenant` attribute mapped to the `tenant_id` claim in `config/keycloak/realm-export.json`), the identifier is pattern-validated in `db/tenancy.py`, and the only seeded scope is `acme`. A name source (new claim vs registry) is a decision, not part of this item.
- Same session, separate idea, not captured here: an acme operator expected to see a handoff that breakglass had written under `platform`. Whether an `admin` may cross the tenant boundary in the handoff queue and ledger is an ADR-005/ADR-022 question of its own and needs its own item if wanted.
