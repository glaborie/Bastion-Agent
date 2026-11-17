### IDEA-068: Give analyst and readonly roles a read-only dashboard

- status: ready
- priority: P2
- phase: v0.4
- area: gateway
- tags: dashboard, rbac, adr-003, adr-007
- depends-on: -
- spec: ADR-007
- created: 2026-11-17
- updated: 2026-11-17
- source: session report on 2026-11-17 ("add to the backlog: give a read-only dashboard to analyst and readonly roles")

**Problem**

The role vocabulary has four roles (`gateway/auth/roles.py`, ADR-003, HANDOVER_SPEC
§3.1) — `admin`, `operator`, `analyst`, `readonly` — and the dashboard only knows
two of them. All nine dashboard routes in `gateway/dashboard/routes.py` are
gated `require_roles("operator", "admin")`, as are the audit API, the approval API
and the demo endpoints; `readonly` appears nowhere in `gateway/` or `db/` outside
the enum itself, and `analyst` appears once, on `POST /v1/chat`, so an analyst may
chat through the API while `/dashboard/chat` refuses it.

A concrete consequence, from PR #90: `carol` (analyst) signs in through Keycloak,
`GET /dashboard` answers `403 Not authorized`, and every navigation link on that
page loops back to the same refusal. The only useful control on the page is the
Sign out that fix added. A `readonly` account is worse off: it can authenticate
and do nothing at all, which in practice pushes people to share an operator login
— the anti-pattern ADR-003 exists to prevent.

The dashboard decision (ADR-007) never says what an analyst is supposed to see, so
this is a decision to record, not only a route to widen.

**Outcome**

An authenticated `analyst` or `readonly` session lands on a dashboard that shows
the evidence its role is for — audit ledger, session inspector, incidents,
handoffs, and the approval queue as a list — with every write path still
`operator`/`admin`. The matrix is decided and recorded (ADR-007 amended or a
superseding ADR, with ADR-003 if the role semantics change), enforced server-side
per route rather than by hiding buttons, and pinned per role by tests: the pages a
role may open answer `200`, the pages and actions it may not answer `403`, and a
`readonly` mutation is refused even when the template would have rendered it.
Tenant scoping and the metadata-only rules of ADR-012 do not change. Whether
`analyst` gets the guarded chat page (the API already accepts that role) and what
`readonly` may see of approvals are decided in that ADR, not left implicit.

**Acceptance**

- [ ] The role/page matrix exists in the ADR (rows: dashboard, audit, session inspector, chat, demo, approvals, handoff and incident panels; columns: the four roles) and states the reason for each cell, including why `readonly` may see an approval list but never a decision
- [ ] Server-side enforcement: a parametrised test iterates roles × routes and asserts the matrix, so a route added later without a role decision fails the suite
- [ ] Every write path stays operator/admin even when the page renders: for `analyst` and `readonly`, a decision `POST`, a demo run `POST` and every mutating dashboard form answer `403`, and the rendered page contains no enabled control that would 403
- [ ] Chat is decided explicitly: if `analyst` may use `/dashboard/chat` (the API already allows it), the page works for that role with the same DLP/route/canary stages; if not, the ADR says why the API and the page differ
- [ ] `admin` still satisfies everything, `readonly` cannot reach any mutating route, and `uv run python scripts/validate_rbac.py` plus `scripts/gate.sh` stay green
- [ ] `README.md` (or `SECURITY.md`) states what each role sees in the dashboard, so the four roles are documented where operators look

**Notes**

- Evidence: `carol` (analyst) at `/dashboard` → `403`; `dave` (readonly) same; the 403 page only gained a Sign out in PR #90, which is what made this gap visible. `POST /v1/chat` accepts `("operator", "analyst", "admin")` while `/dashboard/chat` accepts `("operator", "admin")`, so the split is already inconsistent today.
- Before widening anything, check what the audit and session pages expose: they carry metadata, actor ids and verdicts, not prompt text (ADR-012), but tenant-wide visibility is still a decision — the matrix should say whether analyst/readonly see every actor in the tenant or only their own.
- The approvals list already has a viewer-role notion (`list_pending(viewer_id, viewer_roles)`), so a read-only view is likely a route change plus a template change rather than a new query; verify it refuses decisions server-side instead of relying on the disabled buttons.
- Out of scope: new roles, per-field redaction inside the audit ledger, a separate analyst product surface, and any change to the chat pipeline's stages.
