### IDEA-090: Make a blocked compat turn render a refusal

- status: dropped
- priority: P2
- phase: v0.5
- area: gateway
- tags: chat, openai, prompt-injection, http-errors
- depends-on: -
- spec: ADR-026
- created: 2026-11-20
- updated: 2026-11-20
- source: session report on 2026-11-20 ("every injection case returns 200 with an empty body")

**Problem**

On the OpenAI-compatible surface a detected injection reaches the client as a blank
message: `_completion_body` (`gateway/routers/openai_compat.py:232-259`) sets
`choices[0].message.content` to `""` whenever `response.blocked`, and the SSE replay
(`:275-302`) emits no content delta at all, so the fixed `_INJECTION_NOTICE` that the
native `POST /v1/chat` returns (`gateway/routers/chat.py:114-117`, `:574-585`) is
dropped. A client that renders `content` shows nothing, and the caller cannot tell a
blocked turn from a model that returned no text. `tests/test_openai_compat.py:214`
pins the current shape, and ADR-026 decision 4 records it deliberately (200, empty
`content`, `finish_reason: "content_filter"`, the `bastion` extension), so this is an
amendment to a shipped decision rather than a defect against it.

**Outcome**

A blocked turn on `POST /v1/chat/completions` and on its buffered SSE replay is
visibly distinguishable, in a client that only prints the assistant text, from an
empty model answer: the caller sees a refusal that is attributable to the gateway,
`finish_reason` stays `content_filter`, and the `bastion` extension still carries
`blocked`, `block_reason` and the conversation id. The refusal never becomes model
text, never carries classification detail beyond what that extension already exposes,
and cannot be resent as an assistant turn. Native `/v1/chat`, DLP, routing, egress and
audit behaviour are unchanged, and ADR-026 decision 4 records the amended shape.

**Acceptance**

- [ ] A contract test drives `POST /v1/chat/completions` with an injection prompt and asserts the assistant text is non-empty and identifiable as a gateway refusal, `finish_reason == "content_filter"` and `bastion.blocked is True`, while a turn whose model answer is empty (no block) still differs from it; `tests/test_openai_compat.py:214` is updated rather than relaxed
- [ ] The `stream: true` replay of a blocked turn carries the same visible refusal in its deltas, contains no model text and still terminates with `[DONE]`
- [ ] ADR-026 decision 4 states the amended blocked-turn shape and why the refusal cannot be mistaken for model output; `README.md` documents what a compat client sees on a block; `uv run pytest tests/test_openai_compat.py tests/test_chat.py -q` and `scripts/gate.sh` pass

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `blocked`, `content_filter`, `empty`, `notice` and `refusal`. IDEA-060 (done) introduced this exact shape on the compat facade and ADR-026 decision 4 records it, so this item amends a shipped decision instead of adding a surface; the empty `delivered_text` in IDEA-006/IDEA-012 is the egress canary demo asserting a blocked leak delivered nothing and must stay empty; IDEA-036, IDEA-060 and IDEA-074 touch the same handlers or transcript view but do not cover blocked-turn rendering. No item was merged.
- Open questions for triage: whether the refusal should be an assistant `content` string (which ADR-026 currently forbids because an OpenAI client could mistake it for model text) or an HTTP error envelope (visible to generic clients but breaks the "a completion is a 200" contract); whether the native `_INJECTION_NOTICE` is reused verbatim; whether a normal empty model answer also gets a marker so both directions are distinguishable; and whether streaming emits the refusal as a delta or only in the final chunk.
- Dropped 2026-11-20: the report was a false incident. `200`, empty `content` and `finish_reason: "content_filter"` are the shape IDEA-060 introduced and ADR-026 decision 4 records deliberately, so there is nothing to amend. Reopen only with a concrete client that cannot read the `bastion` extension and is therefore unable to distinguish a block from an empty answer.
- Classification: `P2`/`v0.5`/`gateway`. Usability defect in shipped behaviour with no security invariant relaxed — the guard still refuses before inference and the ledger rows are unchanged — and v0.5 is the current phase. `P3` is defensible if triage reads this as cosmetic; `P1` is not, because nothing is bypassed or leaked.
