### IDEA-103: Align the compat request schema with the roles and fields the route accepts

- status: inbox
- priority: P2
- phase: v0.5
- area: gateway
- tags: openai, openapi, client-compat, chat
- depends-on: -
- spec: ADR-026
- created: 2026-11-20
- updated: 2026-11-20
- source: review of the compat request model, 2026-11-20 ("a generated client builds bodies the server rejects by design")

**Problem**

`CompatRequest` (`gateway/routers/openai_compat.py:90-101`) declares three things the route
always refuses, so the machine-readable contract says "accepted" where the handler says `422`:

- `tools: list[Any] | None` and `tool_choice: Any | None` are advertised as free-form fields,
  but `_to_chat_request` (`:201-206`) rejects any non-`None` value — ADR-026 decision 7 keeps
  tool execution server-side behind the catalog and four-eyes.
- `role: str` on `CompatMessage` (`:86`) advertises every string, while `_to_chat_request`
  (`:209-223`) accepts only `user` and `tool`. `ChatRole = Literal["user", "tool"]` already exists
  (`gateway/routers/chat.py:108`) and is what `ChatTurn` uses; the compat model does not reuse it.

`extra="ignore"` hides the rest, so the only place an unsupported shape is discovered is the
runtime `422`. A client generated from `app.openapi()`, or a typed SDK user reading
`CompatRequest`'s schema, builds a body the document says is valid and the gateway rejects by
design — the exact failure the facade exists to avoid for OpenAI clients.

**Outcome**

Every field and every `role` value the document advertises is one the route accepts:

- `CompatMessage.role` is `ChatRole`, so `system` and `assistant` fail client-side validation
  instead of at the gate, and the schema shows the enum.
- `tools` and `tool_choice` are no longer advertised as accepting a function list or object. The
  conservative shape keeps the fields declared as `None`-only (`tools: None = None`) so a
  populated value is a pydantic validation error and still reaches the client as the enveloped
  `422` ADR-026 decision 7 promises, while the schema cannot be read as support. Removing the
  fields outright is the alternative, but `extra="ignore"` would then swallow them silently, so
  that choice must be recorded in ADR-026 rather than made in the diff.
- The manual refusal branches in `_to_chat_request` either stay as defence in depth or are
  deleted with their pins; neither mypy nor pylint is left flagging unreachable code.
- No accepted request changes behaviour: valid `user`/`tool` turns, `model`, `temperature`,
  `max_tokens` and `stream` are untouched.

**Acceptance**

- [ ] A test reads `app.openapi()["paths"]["/v1/chat/completions"]["post"]["requestBody"]` and
      asserts `messages[].items.role` is an enum of exactly `user` and `tool`, and that no
      filter/object-typed `tools` or `tool_choice` appears in the schema
- [ ] A request whose body matches the document exactly is never refused with `422` by
      `_to_chat_request`, and a `system`-role message is refused by validation (enveloped `422`)
      before the handler — both asserted in `tests/test_openai_compat.py`
- [ ] `tests/test_openai_compat.py:258` still proves a populated `tools` writes no model call and
      enqueues no tool job, whatever status carries the refusal
- [ ] ADR-026 decision 7 records that the request schema now matches the refusal and which of the
      two `tools` shapes was chosen; `uv run pytest tests/test_openai_compat.py tests/test_chat.py
      tests/test_chat_contract.py -q` and `scripts/gate.sh` pass

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `CompatRequest`, `CompatMessage`,
  `tool_choice`, `requestBody`, `role` and `openapi`. IDEA-092/097/100/101 are the response and
  error halves of the same facade; IDEA-095/096/099 change response fields and the `/v1/models`
  role gate; none touches the request model. IDEA-047 fixed the native endpoint's `system` turn,
  IDEA-060 built the compat refusals and ADR-026 decision 7 records them — this item makes the
  document agree with that decision, it does not revisit it. No item merged.
- Open question for triage: whether `temperature` and `max_tokens` deserve schema bounds too
  (`max_tokens` defaults to `1024` only in `_to_chat_request`, `:228`), or whether that belongs
  with the response-schema items. Left out of scope here.
- Same-file collisions: IDEA-100 (200 body), IDEA-097 (SSE) and IDEA-092 (error responses) edit
  the same decorator; this item edits the request model and the validation path, so they can land
  in either order but not on one branch.
