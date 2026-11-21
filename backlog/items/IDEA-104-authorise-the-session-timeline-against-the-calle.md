### IDEA-104: Authorise the session timeline against the caller, not only the tenant

- status: inbox
- priority: P2
- phase: v0.5
- area: security
- tags: multi-tenancy, rbac, audit, dashboard
- depends-on: -
- spec: ADR-007
- created: 2026-11-21
- updated: 2026-11-21
- source: session, review of gateway/audit_service.py session_timeline

**Problem**

`session_timeline` (`gateway/audit_service.py:116`) filters on `tenant_id` and
`session_id` only, so every role in `READ_ROLES` — `readonly` included — can read
another principal's timeline from `/api/sessions/{session_id}/timeline` and
`/dashboard/sessions/{session_id}`. The `session_id` is the caller-chosen
conversation id from `ChatRequest` (`[A-Za-z0-9._:-]{1,128}`), not a server-issued
secret, so it only has to be guessed and `GET /api/audit` already lists it. The
same-tenant case is by design (ADR-007 decision 9, with the tenant-wide
visibility con at line 103), but no test pins it and the ADR says per-actor
visibility needs a new decision rather than a role tweak.

**Outcome**

Either a decided rule that a non-admin reads only its own actor's timeline (and
an unguessable, server-issued conversation id), or an ADR recording that
tenant-wide visibility is deliberate and why a guessable id is acceptable. Whichever
is chosen, the `tenant_id` predicate is covered by a regression test so it cannot
be dropped.

**Acceptance**

- [ ] A test proves one tenant's timeline read cannot return another tenant's rows, and pins the actor rule the decision chose
- [ ] The decision (new ADR, or an amendment to ADR-007) is committed with the change

**Notes**

- No test currently covers tenant isolation on `session_timeline`; that gap is real regardless of which access rule wins.
