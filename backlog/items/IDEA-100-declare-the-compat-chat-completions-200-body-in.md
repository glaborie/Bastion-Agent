### IDEA-100: Declare the compat chat-completions 200 body in the OpenAPI document

- status: ready
- priority: P2
- phase: v0.5
- area: gateway
- tags: openai, openapi, chat, client-compat
- depends-on: -
- spec: ADR-026
- created: 2026-11-20
- updated: 2026-11-21
- source: OpenAPI review of the compat surface, 2026-11-20 ("the primary endpoint is the least specified one")

**Problem**

`POST /v1/chat/completions` returns `Response` and is declared with a bare decorator
(`gateway/routers/openai_compat.py:348`), so `app.openapi()` gives its `200` an empty schema:
`"application/json": {"schema": {}}`. The body the handler actually builds in
`_completion_body` (`:232-259`) — `id`, `object`, `created`, `model`, `choices[].message`,
`choices[].finish_reason` and the `bastion` extension — appears nowhere in the document, so the
one endpoint a client generator is written against is the least specified route in the API.

The two load-bearing semantics of that body are prose only: ADR-026 decision 4 and
`README.md:212` say a blocked turn is `200` with empty `content`, `finish_reason:
"content_filter"` and the `bastion` extension, and `tests/test_openai_compat.py:214` pins it, but
a generated client sees an untyped object and cannot know that `content_filter` is the refusal
signal or what `bastion` contains.

**Outcome**

The document describes the route's `200` body: a schema for the completion object, its
`choices[]` entry (`index`, `message.role`/`message.content`, `finish_reason` as an enum naming
`stop` and `content_filter`) and the `bastion` extension with the members ADR-026 decision 4
records (`blocked`, `block_reason`, `conversation_id`, `route`, `classification`, `confidence`).
The description states that `finish_reason: "content_filter"` with empty `content` and
`bastion.blocked: true` is a policy block, not model text. No behaviour changes: the wire shape,
envelopes and tests stay as they are, and the schema is the one the handler already emits.

**Acceptance**

- [ ] A test reads `app.openapi()["paths"]["/v1/chat/completions"]["post"]["responses"]["200"]` and asserts the schema names `choices` and `bastion` rather than an empty object
- [ ] The `finish_reason` declaration is an enum containing `stop` and `content_filter`, and the response description says the `content_filter` case carries an empty `content` and `bastion.blocked: true` (`tests/test_openai_compat.py:214` remains the behavioural pin)
- [ ] The described fields match `_completion_body` exactly — a test round-trips one emitted completion through the schema, so a field added to the handler without the document fails
- [ ] `uv run pytest tests/test_openai_compat.py tests/test_chat_contract.py -q` and `scripts/gate.sh` pass

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `openapi`, `schema`, `choices`,
  `finish_reason`, `content_filter`, `bastion`. IDEA-092 is the error half of the same decorator
  and IDEA-097 the streaming half; IDEA-095 adds `usage` and IDEA-096 settles `model`, so this item
  documents the body after those land — hence `depends-on`. IDEA-060 built the shape and ADR-026
  decision 4 records it in prose. No item covers the JSON schema itself.
- Correction to the review that produced this item: `finish_reason: "content_filter"` is not
  undocumented — ADR-026 decision 4, `README.md:212` and `tests/test_openai_compat.py:214` all
  record it. What is missing is its presence in the machine-readable document; this item covers
  that, so no separate item was captured for it.
- The `depends-on` was deliberate rather than a phase gate: 095 and 096 change the payload the
  schema must describe, and 097 edits the same `responses` declaration, so landing this first would
  be rebased into a contradiction. Superseded on 2026-11-21: 097 has landed and left
  `application/json` as a bare `type: object` — which tells a generated client nothing — while 095
  and 096 are additive and still untriaged. Documenting the body as it is emitted today is useful on
  its own and extends cleanly when those land, so the dependency is dropped rather than gating this.
