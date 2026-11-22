### IDEA-093: Declare Bearer auth in the OpenAPI document

- status: done
- priority: P2
- phase: v0.5
- area: gateway
- tags: auth, rbac, openapi, client-compat
- depends-on: -
- spec: ADR-001
- created: 2026-11-20
- updated: 2026-11-22
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

- [x] `app.openapi()["components"]["securitySchemes"]` contains an HTTP bearer scheme, and a test asserts it rather than reading the YAML by hand
- [x] The test asserts `/v1/chat` and `/v1/chat/completions` carry that scheme in `security`, while `/health` and `/health/ready` carry none
- [x] The operations that accept the browser session (`/auth/*`) are described without promising Bearer, and `docs/`/`README.md` name the scheme for API clients
- [x] `/v1/chat` declares `401`, `404`, `429` and `504` with the `detail` error schema, so a generated client can model the failures it must handle
- [x] `uv run pytest tests/test_openai_compat.py tests/test_chat.py tests/test_rbac.py -q` and `scripts/gate.sh` pass

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `securityScheme`, `Bearer`, `openapi`.
  ADR-001 decision 2 owns the Bearer-or-session contract and is unchanged by declaring it; no item covers
  the document. IDEA-092 and IDEA-097 document the compat responses of the same routes and do not overlap.
- This is repo-wide rather than compat-only: the same gap hides every route, so triage may prefer to fix
  it as a platform item. `area: gateway` because the app object and the routers both live there.
- Open question for triage: whether CI should also diff the generated document against a committed
  snapshot, which would catch undeclared responses the way IDEA-092 does for one route.
- Implementation: `_declare_openapi_security` post-processes the one generated schema, so the scheme
  and the per-operation requirement live in one place and a new guarded route cannot silently omit
  them; `/health` and `/health/ready` are the explicit exceptions. The `/v1/chat` failure statuses
  (`401`, `404`, `429`, `504`) landed here too because the conformance matrix counts them: 33 response
  declarations + 11 security requirements = 44, `undeclared_status: 0`. The compat route's own error
  set is still IDEA-092. The response fragments moved to `gateway/routers/chat_responses.py` to keep
  `chat.py` under pylint's 1000-line cap (994).
- `/auth/me` does carry `security`, because `get_auth_context` accepts a Bearer token there as well as
  the session cookie; the hidden cookie-only `/auth/login`, `/callback` and `/logout` are not in the
  schema, and the scheme description names the cookie fallback for browser pages.
