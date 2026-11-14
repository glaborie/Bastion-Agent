### IDEA-060: Expose an OpenAI-compatible chat completions facade

- status: inbox
- priority: P2
- phase: v0.5
- area: gateway
- tags: openai, chat, streaming, egress, audit
- depends-on: -
- spec: ADR-012
- created: 2026-11-14
- updated: 2026-11-14
- source: session, design note against gateway/routers/chat.py and README.md:1099, 2026-11-14

**Problem**

`POST /v1/chat` is the only path that reaches a model (`gateway/routers/chat.py:3`) and its body is Bastion's own `ChatRequest` with `extra="forbid"` and `conversation_id`, so an OpenAI client cannot point at the gateway: the request shape, the response shape and the `blocked` flag are all proprietary, and no `/v1/chat/completions` or `/v1/models` route exists. A client already expects the surface — `README.md:1099` records a local client polling `/v1/models` every 30 s, about 11,500 not-found spans a day — so the first real integration would otherwise be written as an external proxy that bypasses the DLP, canary and audit stages entirely. The second obstacle is structural: those stages live inline in the 369-line `chat()` handler (IDEA-036), so adding an adapter without extracting them duplicates the guardrail path, which is the one thing that must not have two implementations.

**Outcome**

`POST /v1/chat/completions` and `GET /v1/models` speak the OpenAI wire format, and both the native endpoint and the adapter call one extracted pipeline function holding the guarded stages, so DLP, routing, canary, injection gate, egress and audit run exactly once. The conversation id comes from `X-Bastion-Conversation-Id` when supplied, otherwise a per-request vault session, with quarantine keyed on the actor for ephemeral sessions because redaction is deterministic per session and clients resend history. `model` is a hint: the classifier's route decision is authoritative, the response reports the model that actually ran, and the aliases `bastion-auto` and `bastion-local` are exposed filtered by the caller's RBAC. A policy-blocked turn is a normal assistant message with `finish_reason: "content_filter"` plus a Bastion extension field; canary trips, quarantine and rate limits use the OpenAI error envelope. Client-supplied `tools` are rejected because tool execution stays server-side behind the catalog and four-eyes. `stream: true` is accepted in the first release by buffering, scanning, then emitting synthetic SSE, so no unscanned byte reaches the caller. Responses API is deliberately out of scope; the ADR records that adding it later is stateless-only — `store: false` forced, `previous_response_id` rejected — because server-side state conflicts with the DLP vault and ledger semantics.

**Acceptance**

- [ ] The official `openai` SDK, pinned in the `dev` dependency group, drives the gateway in a contract test: `client.chat.completions.create(...)` and `client.models.list()` both succeed for an authenticated principal, and the same test asserts a `PUBLIC`, a PII-bearing and a blocked turn; it runs in CI against the ASGI app and is also runnable against a composed stack under `scripts/gate.sh --integration`
- [ ] `stream: true` returns `text/event-stream` whose concatenated deltas equal the non-streaming content for the same input, never contain the canary, and carry no model text when the turn is blocked
- [ ] A blocked turn is HTTP 200 with `finish_reason: "content_filter"`, no model text and the Bastion extension field; a canary trip, an exhausted rate limit and a missing or invalid token each return the OpenAI error envelope (`error.message`, `error.type`, `error.code`) with the existing status codes
- [ ] `model` values that disagree with the route still run the classifier's route, `bastion-local` forces the local alias only when the caller's roles allow it, an unknown alias returns a not-found error envelope, and `response.model` reports the model that actually answered
- [ ] `X-Bastion-Conversation-Id` drives the vault session and is echoed back; without it, two requests from one actor get separate vault sessions and a canary trip quarantines the actor rather than a throwaway session, asserted with live Redis
- [ ] A request carrying `tools` or `tool_choice` is refused with the error envelope, writes no model call and enqueues no tool job
- [ ] `uv run pytest tests/test_openai_compat.py tests/test_chat.py tests/test_chat_contract.py -q` passes, the native `/v1/chat` suite is unchanged, and `scripts/gate.sh --integration` runs the contract test against the composed stack
- [ ] An ADR (new, or an ADR-012 amendment) records the compat surface, the deferred Responses API with its stateless-only rule, the tool rejection and the buffered-streaming boundary; `README.md` documents the base URL and the aliases; `THREAT_MODEL.md` is updated if the new ingress changes a control; `scripts/gate.sh` passes

**Notes**

- Deduplication: no item or ADR defines a public API shape; ADR-012 governs the chat lifecycle every caller must keep, which is why it is the spec. IDEA-036 is the overlapping refactor — it splits the current handler into one function per stage as a pure move — and this item needs that shared function. They are different problems, but they edit the same file: triage should sequence IDEA-036 first or fold its acceptance into this one, otherwise two branches collide. The "client-supplied tools" rejection refers to a tool-execution item that is not captured yet; this item refuses the fields and leaves the execution contract to it.
- Classification: `P2`/`v0.5`/`gateway`. New capability with no invariant broken, and ADR-008 freezes features inside a phase; no phase line names an external API, `v0.5` (production readiness) is the nearest, and `v0.6` (A2A, multi-provider) is the fair alternative. `area: gateway` because the adapter, routes and models list are router code; `agent` fits the streaming egress change and `security` fits the identity and tool-rejection rules.
- Real streaming is a deliberate second slice, not part of this acceptance: a holdback window at least as long as the configured canary (`CANARY_PREFIX` plus a 36-character UUID, `agent/egress/sanitizer.py:167`) and the longest `{{ENTITY:…}}` marker, so a canary or marker straddling two chunks is caught before any of it is released. On a trip the stream terminates and the delivered prefix is recorded with `truncated: true`, hashed incrementally; the disclosure-claim detector runs at end of stream. Its gate is a property-based test that any chunking of any text yields the same released bytes as the non-streaming path and never yields the canary.
- Open questions for triage: whether `/v1/models` answers from the configured alias list or from the caller's RBAC-filtered set (the design implies the latter, which makes the list per token), and whether the compat adapter is a second router module or a path prefix on the existing one. Also undecided: whether the first slice may use the existing `chat()` handler directly and defer the extraction to IDEA-036, at the cost of one duplicated call site instead of one duplicated guardrail path.
