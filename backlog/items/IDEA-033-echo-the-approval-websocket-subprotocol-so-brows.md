### IDEA-033: Echo the approval WebSocket subprotocol so browsers keep the socket open

- status: done
- priority: P1
- phase: v0.3
- area: gateway
- tags: dashboard, websocket, bug, latency
- depends-on: IDEA-002
- spec: ADR-007
- created: 2026-11-12
- updated: 2026-11-12
- source: session report on 2026-11-12 ("the dashboard is polling /api/approvals every 3 seconds and it makes the bottom half of the page blink")

**Problem**

`gateway/dashboard/static/approvals.js:92` opens `new WebSocket(url, ["bastion.csrf." + csrf])`, but `gateway/routers/approval_ws.py:133` calls `await websocket.accept()` with no `subprotocol`. RFC 6455 requires the server to answer a requested subprotocol with `Sec-WebSocket-Protocol`; a browser that offered one aborts the connection when the 101 omits it. The gateway log shows the result: dozens of `WebSocket /ws/approvals [accepted]` lines, one per reconnect, while `approvals.js` treats every close as degradation and starts its 3 s poll. Each poll replaces `#approvals` wholesale, so the lower half of the dashboard blinks every three seconds. The tests missed it because Starlette's `TestClient` records `accepted_subprotocol` without enforcing the rule: `tests/test_approval_ws.py:126` offers the protocol but never asserts the echo.

**Outcome**

The handshake echoes the one offered `bastion.csrf.<token>` subprotocol, a browser keeps the socket open and the page never starts polling, and the fallback poll runs only when the socket really is unavailable. A test asserts the echo and fails against the pre-fix `accept()`.

**Acceptance**

- [x] `websocket.accept(subprotocol=...)` returns the offered `bastion.csrf.<token>` when present and `None` when the client offers none or an unrelated protocol, so query/header clients still connect
- [x] `tests/test_approval_ws.py` asserts `accepted_subprotocol` equals the offered protocol; the assertion fails on the pre-fix code
- [x] Fan-out, tenant isolation, role and CSRF rejections are unchanged
- [x] ADR-007 decision 3 records the echo requirement; `uv run python scripts/check_adrs.py` passes
- [x] `scripts/gate.sh --integration` is green (10/10: 768 passed / 16 skipped, mypy 80 files, pylint 10.00/10), after repairing two base lints inherited from `origin/master` (`wiki/API-Reference.md` code block, `tests/test_db_tls.py` empty-mapping assertion)

**Notes**

- Root cause, not a reconnect heuristic: the ASGI handshake was accepted and uvicorn logged `[accepted]`, but the browser closed the socket immediately because the response carried no `Sec-WebSocket-Protocol` for the protocol it requested.
- Verification is at the ASGI handshake (`accepted_subprotocol`) plus the existing two-client fan-out tests. No browser was run.
- Honest limit: the degraded path still replaces `#approvals` wholesale every 3 s, which is the documented fallback; skipping a no-op swap is a separate improvement, not part of this fix.

**Implementation notes (2026-11-12)**

- Red first: the new assertion in `tests/test_approval_ws.py` failed against the shipped code (`accepted_subprotocol` was `None`), so the test pins the actual defect rather than the fix.
- Fix shape: `_csrf_carrier()` selects exactly the offered `bastion.csrf.<token>` protocol, `_csrf_from_subprotocol()` reuses it, and `approvals_stream` now calls `await websocket.accept(subprotocol=_csrf_carrier(websocket))`. A client offering no protocol (query/header token) still connects with no selected protocol; an unrelated protocol such as `graphql-ws` is never echoed.
- Live proof against the rebuilt `bastion-agent:local`: seeded a throwaway operator session in Redis, sent a raw RFC 6455 upgrade to `localhost:8000/ws/approvals` with the CSRF subprotocol, and got `HTTP/1.1 101 Switching Protocols` plus `Sec-WebSocket-Protocol: bastion.csrf.live-check-csrf`. Before the fix that header was absent — uvicorn still logged `[accepted]`, which is why the symptom looked like a reconnect problem rather than a handshake failure. The throwaway session was deleted afterwards.
- Base repair: `origin/master` (wiki + mTLS PRs) carried two repo-wide gate failures that arrived after the base I branched from — `ruff 0.17.4` reformats a Python block in `wiki/API-Reference.md`, and pylint flags `redis_tls_kwargs(settings) == {}` in `tests/test_db_tls.py`. Both are one-line, behaviour-free fixes kept in their own commit so this branch's gate is honest; they are unrelated to the socket.
- Tests: `tests/test_approval_ws.py` now also proves that a client offering no protocol, and one offering only an unrelated protocol, still connect. Fan-out, tenant isolation, `readonly` and CSRF rejection tests are unchanged and green.
- Limitation worth recording: the `websockets` library (17.4) returns `None` instead of failing when a server omits the echo, so only a real browser enforces RFC 6455 here. The ASGI-level assertion is the contract the browser checks; the raw upgrade above confirms uvicorn writes the header.
