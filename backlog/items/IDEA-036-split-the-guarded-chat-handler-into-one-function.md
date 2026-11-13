### IDEA-036: Split the guarded chat handler into one function per lifecycle stage

- status: inbox
- priority: P3
- phase: v0.3
- area: gateway
- tags: chat, refactor, egress, dlp, audit
- depends-on: -
- spec: ADR-012
- created: 2026-11-12
- updated: 2026-11-12
- source: review of gateway/routers/chat.py, 2026-11-12

**Problem**

`chat()` in `gateway/routers/chat.py` runs from line 290 to line 658 (369 lines) and interleaves five stages — DLP redaction, routing/classification, the injection gate, egress inspection, and the delivered-response audit — with audit commits, span annotations and error branches inline. Two small redundancies ride along: the `except (DLPUnavailableError, VaultError)` branch at line 345 and the following `except Exception` branch at line 348 have identical bodies (same log line, same 503, same message), and `_blocked()` at line 275 is a one-line alias for `HTTPException` used only to shorten eight raise sites. The stage boundaries are marked by comments, so a reader must re-derive the state passed between stages from 369 lines of straight-line code, which makes any edit to one stage hard to review against commit order.

**Outcome**

`chat()` becomes a short orchestrator that calls one function per stage with explicit state (an intermediate carrying the request, auth context, session, redacted messages, classification, route decision, canary and completion). The redundant DLP branches collapse into one, and `_blocked()` is removed in favour of raising `HTTPException` directly. This is a pure move: control flow, audit commit order, audit fields, span attributes and response status codes are unchanged.

**Acceptance**

- [ ] `chat()` is at most 80 lines, and no stage body remains inline: each of the five stages is a named function called from the orchestrator, verified by reading the handler and by a line count of the `chat` function
- [ ] `uv run pytest tests/test_chat.py tests/test_chat_contract.py -q` passes with no assertion added, removed or loosened
- [ ] Every stage still writes its existing audit event and sets its span attributes in the same order as today: `INPUT_RECEIVED`, `DLP_REDACTION`, `ROUTING_DECISION`, `RESPONSE_SENT`, `EGRESS_FILTERED` and `SECURITY_INCIDENT` appear in the same sequence and with the same metadata keys for a normal turn and for the blocked paths (circuit open, injection, canary leak)
- [ ] `uv run mypy gateway/routers/chat.py` and `uv run ruff check gateway/routers/chat.py` pass

**Notes**

- Deduplication: no open or done item and no ADR decision covers the handler's structure. IDEA-018 (escalation), IDEA-027 (completion cache) and IDEA-028 (complexity routing) add behaviour at this endpoint, not a decomposition; ADR-012 governs the egress contract the stage must keep, which is why it is the spec.
- The DLP generic branch carries an explanatory comment that the first branch does not; keeping that comment on the merged branch preserves the intent. Removing `_blocked()` touches eight raise sites, all inside this handler.
