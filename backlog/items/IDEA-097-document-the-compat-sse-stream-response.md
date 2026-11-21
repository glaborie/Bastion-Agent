### IDEA-097: Document the compat SSE stream response

- status: ready
- priority: P3
- phase: v0.5
- area: gateway
- tags: openai, streaming, openapi
- depends-on: -
- spec: ADR-026
- created: 2026-11-20
- updated: 2026-11-21
- source: six-finding OpenAPI review of the compat surface, 2026-11-20

**Problem**

`CompatRequest.stream` is accepted (`gateway/routers/openai_compat.py:99`) and the route branches on it at
`:382-385`, returning a `StreamingResponse` with `media_type="text/event-stream"` built by
`_synthetic_sse` (`:275-302`) — chunks of `chat.completion.chunk`, terminated by `[DONE]`
(ADR-026: the SSE is a buffered, scanned replay, not a live increment).

The OpenAPI document knows none of this: the bare decorator declares `200` with no content type
(the default `application/json`) and `422`. A generated client builds a non-streaming call and a reader
cannot learn that `text/event-stream` is the answer to `stream: true`, what the chunk object looks like,
or that the stream is buffered.

**Outcome**

The document declares the route's `200` with two media types, `application/json` and
`text/event-stream`, the latter with a `chat.completion.chunk` schema (including the `bastion` extension
on the terminal chunk) and a note that the stream is a replay with `[DONE]` as its terminator. A client
generator can therefore produce a streaming call, and a reader can see that no incremental token reaches
them before the scan — which is a property worth documenting, not hiding.

**Acceptance**

- [ ] `app.openapi()["paths"]["/v1/chat/completions"]["post"]["responses"]["200"]["content"]` lists both media types, asserted by a test rather than by reading the YAML
- [ ] The `text/event-stream` schema describes the chunk object and names `[DONE]`; the buffered-replay property is stated in the document text
- [ ] `README.md` or `docs/` describes what a compat client receives with `stream: true`
- [ ] `uv run pytest tests/test_openai_compat.py tests/test_chat_contract.py -q` and `scripts/gate.sh` pass

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `stream`, `event-stream`, `sse`.
  ADR-026 decision 5 records the buffered replay; IDEA-060 built it; no item or ADR records what the
  document says. IDEA-092 is the error-response half of the same decorator and is kept separate because
  the two can land independently.
- `P3`: documentation only, nothing about the wire format changes, and a client that already passes
  `stream: true` works today.
- Open question for triage: whether a streaming entry also belongs on the native `/v1/chat` (which does
  not stream at all today) or whether the document should say so explicitly to stop a client guessing.
