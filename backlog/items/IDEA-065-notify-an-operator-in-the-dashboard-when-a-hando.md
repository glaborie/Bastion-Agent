### IDEA-065: Notify an operator in the dashboard when a handoff is queued

- status: done
- priority: P2
- phase: v0.4
- area: gateway
- tags: dashboard, handoff, notifications, breakglass, htmx
- depends-on: IDEA-018
- spec: ADR-022
- created: 2026-11-17
- updated: 2026-11-17
- source: session request on 2026-11-17 ("a separate browser with breakglass logged in should receive a browser notification")

**Problem**

IDEA-018 detects a frustrated conversation and writes `HANDOFF_REQUIRED`, and ADR-022 decision 5 ships exactly one operator surface for it: `GET /api/handoffs` (`gateway/dashboard/routes.py:123`), twenty newest rows, `require_roles("operator", "admin")`. Nothing in the dashboard consumes it. A repo-wide search finds `handoff` only in that route, in `recent_handoffs` and in the audit page's event-type filter — `grep -rn handoff gateway/dashboard/templates/` is empty — because decision 6 states "the dashboard is not the destination" and the panel was deferred.

The concrete miss, from a live stack: conversation `6fb2af8453734dfd97025541ab9196ed` produced audit row 763 `HANDOFF_REQUIRED` at `2026-11-17T13:47:46.151980Z` with `{"markers":3,"verdict":"escalating_language","user_turns":2}`, and `/api/handoffs` lists it. The operator was sitting on `/dashboard/chat` and saw nothing — no badge, no row, no notice — and concluded detection had failed, which sent this discovery down a stale-image investigation first (PR #85). A queued handoff is therefore invisible unless someone remembers to open `/dashboard/audit?event_type=HANDOFF_REQUIRED` or call the JSON endpoint by hand, and a second browser signed in as `breakglass` (the seeded admin, `DEMO.md` line 75) has no way to learn that a conversation is waiting.

**Outcome**

An operator/admin session learns about a queued handoff without leaving the page it is on, and a second signed-in browser receives a browser notification for it, so the queue stops depending on somebody refreshing an audit page. The decision is recorded before it is built: ADR-022 decision 5 ("one operator surface") and decision 6 ("the dashboard is not the destination") change, in a new or superseding ADR, with the limits this item cannot remove — the notification is delivered by the browser that is open and has been granted `Notification` permission, nothing pages a person whose browser is closed, and the queue still carries metadata only. No transcript text, no new service and no third-party push provider enter the picture; `breakglass` is a seeded admin session like any other, so the notification rides the same role gate rather than a bespoke channel.

**Acceptance**

- [x] A queued handoff appears in the dashboard without a manual refresh: the shared header (or the chat page) polls the existing queue endpoint and renders the conversation id, verdict and time, and a test asserts a row created between two polls shows up on the second
- [x] A browser signed in as `breakglass` in a second session receives one `Notification` for a newly queued handoff, generated client-side from the queue payload; a test asserts the notification body carries the conversation id and verdict and no list of the conversation's turns or messages
- [x] The role gate is unchanged: `readonly` and `analyst` still get `403` from `/api/handoffs`, the panel is not rendered for them, and no notification is produced, asserted per role
- [x] One notification per handoff id per browser: a poll that returns the same rows again does not notify twice, and a dismissed or denied permission does not break the page (the panel still renders)
- [x] Metadata only end to end: a test asserts the queue response has no transcript field, and the client builds the notification text from the id, verdict and timestamp alone
- [x] The governing ADR exists or ADR-022 is superseded/amended in the same change, `uv run python scripts/check_adrs.py` passes, and `README.md` documents where an operator sees a handoff and what the browser notification requires (signed-in session, permission, page open)
- [x] `uv run python scripts/check_backlog.py --check` passes and `scripts/gate.sh` is green

**Notes**

- Implementation: `GET /api/handoffs/panel` (`gateway/dashboard/routes.py`) renders `partials/handoff_panel.html` under the same `require_roles("operator", "admin")` gate as the JSON queue; `base.html` adds an `#handoff-slot` for those roles that polls it (`load, every 15s, visibilitychange, focus`) and `static/handoffs.js` raises the notification. The fragment carries `data-handoff-id`, `data-handoff-verdict` and `data-handoff-created` only.
- Verified live against the running stack after rebuilding the gateway: the fragment rendered the real earlier handoff `6fb2af8453734dfd97025541ab9196ed` (`escalating_language`, `2026-11-17 13:47:46Z`) and `GET /dashboard` as an operator contains `id="handoff-slot"`.
- The notification path was executed against a stub of the `Notification` API with the shipped script (not a reimplementation): the first poll notified 0 times, a row queued between polls produced exactly one call with body `repeated_complaint · conversation conv-b · 2026-11-17 13:47:46Z` and tag `bastion-handoff-conv-b`, a repeat poll produced none, permission `denied` raised nothing and threw nothing, and the button appeared only while the permission was `default`. No operating-system popup was observed in a real browser in this run; clicking **Enable browser alerts** once is the operator step.
- Tests: `tests/test_handoffs_panel.py` (8, non-integration) pins the role-gated wiring, the attributes-only fragment, the empty state and the script/attribute coupling; `tests/test_dashboard.py` gains two integration tests (a row queued between two polls appears on the second; `readonly`/`analyst` get `403` and no slot, and the JSON queue keys are exactly `conversation_id`, `verdict`, `created_at`).
- ADR-022 decisions 5 and 6 are amended and a new decision 8 records the client-side, metadata-only notification with its limits (browser open, permission granted, nothing pages a closed browser).
