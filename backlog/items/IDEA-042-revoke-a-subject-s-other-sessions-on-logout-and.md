### IDEA-042: Revoke a subject's other sessions on logout and surface a stale-tab CSRF rejection

- status: done
- priority: P2
- phase: v0.3
- area: gateway
- tags: auth, sessions, csrf, logout, observability
- depends-on: -
- spec: ADR-007
- created: 2026-11-13
- updated: 2026-11-13
- source: local-stack debugging session on 2026-11-13 (repeated `CSRF check failed` warnings for subject `dba52e17-…`)

**Problem**

Every sign-in creates a new server-side session (`gateway/auth/session.py:155-171`) and replaces the shared `bastion_session` cookie (`gateway/routers/auth.py:135-145`), but nothing retires the session the cookie used to point at. `/auth/logout` calls `sessions.delete(session_id)` for the presented cookie only (`gateway/routers/auth.py:186-193`), and `SessionManager` has no reverse index from subject to sessions, so there is no way to list or revoke a subject's other sessions. Each orphan keeps its access and refresh token for the full 8 h TTL (`SESSION_TTL_SECONDS`, `docker-compose.yml`).

Three consequences, all observed on the running stack:

1. **Stale tabs fail silently.** CSRF tokens are per session, so a document rendered before a re-login carries a token that no longer matches the cookie the browser now sends. The mutation is correctly rejected (`gateway/auth/rbac.py:321-326`) with a bare `403 "CSRF token missing or invalid"`; htmx renders it as an alert and the operator has no idea a reload fixes it (ADR-007 only requires the check, not the recovery).
2. **The warning cannot be attributed.** It logs `subject` only, and `logging_setup.py:84` disables uvicorn access logs with no request-log replacement, so nothing anywhere records which endpoint failed. A wrong token (stale document) and a missing token (non-browser client) look identical.
3. **Sign-out is not global.** Sessions created before the last login stay live. Observed after a logout/login cycle: `_yxrHdDA` (13:09:08, current), `BWivNjeg` (12:52:40) and `YEvbkf7B` (12:43:25) all present in Redis for the same subject, the oldest predating two logouts. The orphaned cookie is gone from that browser, but a second browser or device that logged in earlier keeps a working session after "Sign out", and nothing in the dashboard can end it.

**Outcome**

Sign-out ends the subject's sessions, not just the current one: sessions carry the subject index (`auth:sessions:<subject>` → session ids, or a subject-scoped key prefix) so logout deletes the current session and offers/allows revocation of the rest, and the index is pruned on expiry. A stale-tab CSRF rejection becomes actionable: the 403 carries `HX-Redirect: /dashboard` for htmx callers so the tab reloads with the current session instead of showing a dead alert, and the warning records the endpoint and whether a token arrived at all, so the next occurrence needs no guesswork. No token value is ever logged.

**Acceptance**

- [x] A session created at sign-in is reachable from its subject, and `SessionManager.delete_all_for_subject(subject)` removes every session for that subject; a unit test seeds two sessions for one subject plus one for another and asserts only that subject's records are gone
- [x] `POST /auth/logout` revokes the presented session (as today) and the subject's other sessions; a test with two live sessions for one subject signs out through one and asserts both Redis keys are gone
- [x] logout stays a redirect to the one-time `/auth/logged-out` landing page and its existing session-deletion path, and does not become a global "log out every Keycloak SSO session" call (the IdP end-session flow is unchanged)
- [x] the subject index cannot outlive its sessions: an expired session's id is dropped from the index (lazy prune on write is enough), and a test proves an index entry does not resurrect a missing session
- [x] a CSRF mismatch on an htmx request answers `403` with `HX-Redirect: /dashboard` instead of an HTML alert, and a non-htmx or non-browser caller still gets the JSON `403`; tests cover both
- [x] the `CSRF check failed` warning carries the request path and whether a token was presented (`path`, `token_presented`, `content_type`), proven by a `caplog` assertion, and no token, cookie or secret value appears in any log line
- [x] a stale-tab round trip is demonstrated end to end on the local stack: render a page, sign in again, POST a mutation from the first document, observe the redirect to a working page rather than a dead end
- [x] `uv run pytest -q`, `ruff check .`, `ruff format --check .`, `mypy`, `pylint`, `check_backlog.py --check` stay green (`scripts/gate.sh`)
- [x] ADR-007 decision 5 states that logout ends every session of the subject and describes the stale-document recovery, and `docs/TROUBLESHOOTING.md` names the `CSRF check failed` warning with the re-login cause and the recovery

**Notes**

- Evidence, not theory: with `OMNIROUTE_API_KEY` broken the chat 502 was the visible failure, but the CSRF warnings reproduced independently. The failing POST authenticated against the newest session (its Redis `last_seen` matched the warning timestamp to the millisecond) while a document from an older session was still open, which is exactly the shape predicted by per-session tokens plus a replaced cookie. The log could not name the endpoint, which is why attributability is part of the acceptance.
- Classification: `P2`/`v0.3`/`gateway`. The stale-tab 403 is reachable in normal use and the logout gap is a control-plane smell, but the orphaned cookie never reaches the browser again, so exposure needs a second browser or device that had logged in; promote to `P1` if global sign-out is declared a requirement. The change is confined to `gateway/auth/`, `gateway/routers/auth.py`, `gateway/main.py` (htmx 403 handling) and one template, which is the current phase's dashboard/auth work.
- Rejected alternatives: rotating the CSRF token on refresh (does not help — the cookie changed, not the token), accepting a token from any live session of the same subject (weakens CSRF to "logged in at some point"), and a login-per-session cookie name (breaks the single opaque cookie ADR-007 chose).
- Deduplication: grepped `backlog/items/` for `session`, `logout`, `csrf`, `stale`, `tab` and `redis`. IDEA-001 is tenant isolation for Redis keys and Postgres rows, IDEA-002 is approval delivery over WebSocket, and the CSRF mentions in IDEA-040 are about hop encryption. Nothing covers session revocation or the CSRF-warning diagnosability, so nothing was merged.
- Out of scope: a dashboard session list with per-session revoke (a UI feature), WebSocket handshake behaviour for a session revoked mid-connection, and rate limiting (ADR-013).
- Implemented summary: `_save` adds the id to `auth:subject-sessions:<subject>` and refreshes that set's TTL, `delete` removes the member, and `delete_all_for_subject` deletes the member keys plus the set; `/auth/logout` still deletes the presented session first, so the control does not depend on the index being present. Membership stays advisory — only `auth:session:<id>` authenticates, so a leftover id resolves to nothing. Sessions created before this change carry no index member, so their revocation falls back to TTL; `docs/TROUBLESHOOTING.md` says so.
- redis-py types an unparameterised async client's coroutine methods as `T | Awaitable[T]`; the three `cast(Awaitable[...])` calls in `gateway/auth/session.py` are type-only and do not change runtime behaviour.
