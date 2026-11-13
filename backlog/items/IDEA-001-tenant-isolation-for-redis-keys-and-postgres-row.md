### IDEA-001: Tenant isolation for Redis keys and Postgres rows

- status: done
- priority: P2
- phase: v0.3
- area: agent
- tags: multi-tenancy, redis, postgres, rbac
- depends-on: -
- spec: ADR-008
- created: 2026-11-09
- updated: 2026-11-11
- source: ADR-008, phase v0.3 scope

**Problem**

Every subsystem assumes a single tenant: the vault key is
`vault:<sha256(session)>`, canaries are per session, quarantine is per session and
audit rows carry no tenant. Two customers on one stack would share a Redis
namespace and a Postgres schema, so one operator role could reach the other
tenant's data through a guessed identifier.

**Outcome**

Every derived key and every audit row is scoped by a tenant id that
comes from the authenticated identity, cross-tenant access is impossible by
construction, and a test proves it by attempting the access.

**Acceptance**

- [x] Tenant id resolved from the OIDC claim and stored on `PendingApproval` and `AuditLog`
- [x] Vault, canary, quarantine and approval keys include the tenant prefix
- [x] A test shows a session from tenant A cannot read a token or ticket from tenant B
- [x] ADR documents the isolation model before implementation

**Notes**

- PostgreSQL row-level security is not part of this change: it remains the v0.3 defence-in-depth step named in ADR-008 and ADR-015 decision 6. Request-path reads are tenant-scoped in the shared query helpers.
