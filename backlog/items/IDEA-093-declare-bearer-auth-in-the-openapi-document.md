### IDEA-093: Declare Bearer auth in the OpenAPI document

- status: inbox
- priority: P2
- phase: v0.5
- area: gateway
- tags: auth, rbac, openapi, client-compat
- depends-on: -
- spec: ADR-001
- created: 2026-11-20
- updated: 2026-11-20
- source: six-finding OpenAPI review of the compat surface, 2026-11-20

**Problem**

The app is built in `gateway/main.py:95-114` with `openapi_tags` but no `components.securitySchemes`,
and nothing under `gateway/` uses `Security()` or `HTTPBearer` — protected routes take
`Depends(require_roles(...))` (`gateway/auth/rbac.py`), which reads the `Authorization` header by hand
(`:44`; token validation in `gateway/auth/oidc.py:171`). So the document declares every endpoint public
while the runtime answers `401` without a token.

Consequences: an OpenAPI generator produces a client with no auth parameter, the "Try it out" button in
`/docs` cannot send a token, and a reader cannot learn the scheme — Bearer for API clients, an HttpOnly
session cookie for the browser flow (ADR-001 decision 2) — from the spec at all.

**Outcome**

`components.securitySchemes` declares the Bearer scheme (HTTP, `bearer`), every authenticated operation
carries `security`, and the unauthenticated probes (`/health`, `/health/ready`) carry none. The document
states which endpoints also accept the browser session instead of Bearer, so a reader is not told the
cookie paths need a token they do not have. Nothing about authentication changes at runtime: `401`
behaviour, RBAC, CSRF and cookie scoping stay as they are, and the existing tests pass unchanged.

**Acceptance**

- [ ] `app.openapi()["components"]["securitySchemes"]` contains an HTTP bearer scheme, and a test asserts it rather than reading the YAML by hand
- [ ] The test asserts `/v1/chat` and `/v1/chat/completions` carry that scheme in `security`, while `/health` and `/health/ready` carry none
- [ ] The operations that accept the browser session (`/auth/*`) are described without promising Bearer, and `docs/`/`README.md` name the scheme for API clients
- [ ] `uv run pytest tests/test_openai_compat.py tests/test_chat.py tests/test_rbac.py -q` and `scripts/gate.sh` pass

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `securityScheme`, `Bearer`, `openapi`.
  ADR-001 decision 2 owns the Bearer-or-session contract and is unchanged by declaring it; no item covers
  the document. IDEA-092 and IDEA-097 document the compat responses of the same routes and do not overlap.
- This is repo-wide rather than compat-only: the same gap hides every route, so triage may prefer to fix
  it as a platform item. `area: gateway` because the app object and the routers both live there.
- Open question for triage: whether CI should also diff the generated document against a committed
  snapshot, which would catch undeclared responses the way IDEA-092 does for one route.
