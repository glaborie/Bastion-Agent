### IDEA-068: Give analyst and readonly roles a read-only dashboard

- status: done
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

- [x] The role/page matrix exists in the ADR (rows: dashboard, audit, session inspector, chat, demo, approvals, handoff and incident panels; columns: the four roles) and states the reason for each cell, including why `readonly` may see an approval list but never a decision
- [x] Server-side enforcement: a parametrised test iterates roles × routes and asserts the matrix, so a route added later without a role decision fails the suite
- [x] Every write path stays operator/admin even when the page renders: for `analyst` and `readonly`, a decision `POST`, a demo run `POST` and every mutating dashboard form answer `403`, and the rendered page contains no enabled control that would 403
- [x] Chat is decided explicitly: if `analyst` may use `/dashboard/chat` (the API already allows it), the page works for that role with the same DLP/route/canary stages; if not, the ADR says why the API and the page differ
- [x] `admin` still satisfies everything, `readonly` cannot reach any mutating route, and `uv run python scripts/validate_rbac.py` plus `scripts/gate.sh` stay green
- [x] `README.md` (or `SECURITY.md`) states what each role sees in the dashboard, so the four roles are documented where operators look

**Notes**

- Evidence: `carol` (analyst) at `/dashboard` → `403`; `dave` (readonly) same; the 403 page only gained a Sign out in PR #90, which is what made this gap visible. `POST /v1/chat` accepts `("operator", "analyst", "admin")` while `/dashboard/chat` accepts `("operator", "admin")`, so the split is already inconsistent today.
- Before widening anything, check what the audit and session pages expose: they carry metadata, actor ids and verdicts, not prompt text (ADR-012), but tenant-wide visibility is still a decision — the matrix should say whether analyst/readonly see every actor in the tenant or only their own.
- The approvals list already has a viewer-role notion (`list_pending(viewer_id, viewer_roles)`), so a read-only view is likely a route change plus a template change rather than a new query; verify it refuses decisions server-side instead of relying on the disabled buttons.
- Out of scope: new roles, per-field redaction inside the audit ledger, a separate analyst product surface, and any change to the chat pipeline's stages.
- Implementation: the role sets live in `gateway/auth/roles.py` — `READ_ROLES` (all four), `WRITE_ROLES` (`operator`, `admin`) and `CHAT_ROLES` (`operator`, `analyst`, `admin`) — and every dashboard route and API dependency takes one of them, so a page, its APIs and the template that links to them read the same tuple. `templating.py` exposes `has_role(principal, roles)` to Jinja and the Chat/Demo nav links are conditioned on `CHAT_ROLES`/`WRITE_ROLES`; the handoff panel stays operator/admin, and `ApprovalView.decidable` already required the viewer to satisfy the ticket's role, so no decision form renders for an analyst or a viewer.
- The matrix, with a reason per cell, is ADR-007 decision 9: read surfaces (dashboard, audit + chain check, session inspector, incidents, eval health, approval list) are open to all four roles; approving, demo runs, handoff acknowledgement stay `operator`/`admin`; chat is `operator`/`analyst`/`admin` so the page matches `/v1/chat`; the escrow transcript and the escrow API stay `admin`; `readonly` gets the read surfaces and nothing that acts.
- The one POST a `readonly` session may make is `/dashboard/theme`: it writes an allow-listed display cookie and no tenant data, and blocking it would trap a viewer in the wrong palette. That exception is in the matrix rather than implied, because the acceptance says "no mutating route" — this is the display preference, not evidence or state.
- Tests: `tests/test_dashboard_roles.py` (new, 17 passed) holds the matrix as data (`ROLE_MATRIX`: dashboard, audit, sessions, verify, incidents, approvals list, evals, handoffs, chat, demo, the four-eyes action) and iterates roles × routes, asserts a viewer's `/dashboard` renders no approval form, no handoff slot and no demo link, that a readonly page has no Chat link while an analyst's does, and that a demo run POST is refused for both; a route added without a row fails the suite. `tests/test_dashboard.py` updated where the old matrix was asserted (approval list readable but decision 403, incident panel readable, chat page analyst 200 / readonly 403, the 403-page test now uses `/dashboard/demo`), and `tests/test_dashboard_theme.py` now asserts a viewer keeps its colour preference. No existing security assertion was weakened: the write paths answer 403 exactly as before.
- `tests/test_dashboard.py` crossed pylint's 1000-line cap when the matrix landed, so the fixture body moved into `dashboard_app()` and the matrix lives beside it in `tests/test_dashboard_roles.py`; `tests/test_dashboard.py` is 973 lines.
- Gates: `scripts/gate.sh` 13/13, `validate_rbac.py` included; the DB-backed suites (dashboard, roles, chat, rbac, theme, sentiment, audit chain) 121 + 86 passed against a throwaway PostgreSQL. README's demo-user table and a new "What each role sees" paragraph match the ADR.
