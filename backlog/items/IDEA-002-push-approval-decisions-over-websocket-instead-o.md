### IDEA-002: Push approval decisions over WebSocket instead of 3 s polling

- status: done
- priority: P1
- phase: v0.3
- area: gateway
- tags: dashboard, websocket, hitl, latency
- depends-on: -
- spec: ADR-007
- created: 2026-11-09
- updated: 2026-11-11
- source: ADR-008, phase v0.2 scope

**Problem**

The dashboard polls `/api/approvals` every 3 seconds, so a second
operator can wait up to 3 seconds to see a ticket and every open tab generates
traffic that had to be excluded from tracing.

**Outcome**

The dashboard receives `APPROVAL_REQUESTED` and decision events on a
WebSocket, polling becomes a fallback, and the tracing exclusion for the poll URL
can be removed.

**Acceptance**

- [x] `/ws/approvals` authenticated by the same session cookie and CSRF rules
- [x] Ticket creation and decision broadcast to every connected operator
- [x] Polling remains as a degraded fallback when the socket cannot connect
- [x] A test drives two clients and asserts both see the decision

**Notes**

- The bus is Redis pub/sub on `approvals:events:<tenant>`: the worker and demo scenarios publish ticket creation after the database commit, and the decision route publishes `APPROVAL_GRANTED`/`APPROVAL_REJECTED` after its commit. A publish failure is logged and swallowed; the dashboard's 3 s polling remains the recovery path.
- The browser sends the CSRF token in the `bastion.csrf.<token>` WebSocket subprotocol so it stays out of the URL and access logs; the query parameter and `X-CSRF-Token` are accepted for non-browser clients.
- Residual: `/ws/approvals` is authenticated and read-only but is not covered by ADR-013's HTTP request budget, and the JS polling fallback is covered by code inspection rather than a browser E2E harness. The socket protocol, tenant isolation, two-client fan-out and publish-after-commit paths are tested.
