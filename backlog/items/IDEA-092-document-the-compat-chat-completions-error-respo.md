### IDEA-092: Document the compat chat-completions error responses

- status: active
- priority: P2
- phase: v0.5
- area: gateway
- tags: openai, chat, http-errors, openapi
- depends-on: -
- spec: ADR-026
- created: 2026-11-20
- updated: 2026-11-22
- source: six-finding OpenAPI review of the compat surface, 2026-11-20

**Problem**

`POST /v1/chat/completions` is declared with a bare decorator (`gateway/routers/openai_compat.py:348`),
so the generated OpenAPI document lists only `200` and FastAPI's automatic `422`. The route actually
answers through `_envelope_for` (`:120-142`), which has an entry for `400`, `401`, `403`, `404`, `413`,
`422`, `429`, `502` and `503` — every one of them an OpenAI-shaped error envelope with `type` and `code`.
A client generated from the document therefore has no error model at all, and cannot tell that `401`
means a bad token rather than a malformed body.

The sibling native route does better but inconsistently: `/v1/chat` documents `403`, `413`, `422`,
`502` and `503` (`gateway/routers/chat.py:966-976`) and omits `401`, `404`, `429` and `504` it can also
raise. Two endpoints on the same pipeline advertise different, both incomplete, contracts.

**Outcome**

The document for `/v1/chat/completions` lists every status `_envelope_for` can produce, each with the
envelope schema (`error.type`, `error.code`, `error.message`), and `/v1/chat` lists its own full set
including `401`. The two lists are derived from one place — the status map the handler already uses, or a
single declared table — so adding a status to `_envelope_for` without documenting it fails a test rather
than drifting. Behaviour, envelopes and existing tests are unchanged: this is a contract that becomes
honest, not a different one.

**Acceptance**

- [ ] A test reads `app.openapi()` and asserts the documented status set of `/v1/chat/completions` equals the keys of the `_envelope_for` mapping, so a new handler status without a documented response fails
- [ ] The same test asserts `/v1/chat` documents `401` and every other status its handler can raise, and that both endpoints describe the shared envelope rather than an empty object
- [ ] `uv run pytest tests/test_openai_compat.py tests/test_chat.py tests/test_chat_contract.py -q` and `scripts/gate.sh` pass, and the committed `README.md` wording for the compat error shape matches the document

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `openapi`, `securityScheme`, `responses`,
  `http-errors`. IDEA-060 (done) built the facade and ADR-026 records the envelope, but neither records
  what the document says; IDEA-036 and IDEA-074 touch adjacent handlers without covering declarations.
  No item was merged. IDEA-097 is the streaming half of the same decorator and is kept separate on
  purpose.
- Open questions for triage: whether the `429` token-budget variant (`code: token_budget_exhausted`) and
  the quarantined `403` (`code: session_quarantined`) get their own documented entries or one entry with
  examples; whether a test may import the private mapping or the handler should export it.
