### IDEA-106: Declare the compat 405 and drop the unreachable 400 from the OpenAPI document

- status: ready
- priority: P2
- phase: v0.5
- area: gateway
- tags: openai, chat, http-errors, openapi, client-compat
- depends-on: IDEA-092
- spec: ADR-026
- created: 2026-11-22
- updated: 2026-11-22
- source: verification comment on issue #161, 2026-11-22

**Problem**

IDEA-092 made the document match the runtime for the statuses the facade raises, but the
`COMPAT_ERRORS` table it introduced declares one status nothing raises and misses one thing that is
reachable.

- `400` is declared and unreachable. The table was inherited from `_envelope_for`, and no code path on
  a compat path raises `HTTPException(400)`: `gateway/routers/chat.py`, `gateway/rate_limit.py`,
  `gateway/routers/openai_compat.py` and the auth dependencies produce `401/403/404/413/422/429/502/503`
  (plus `504` on the native route) only. Grepping `gateway/` for `HTTP_400` finds `routers/auth.py` and
  `approvals.py`, neither of which is a compat path.
- `405` is reachable and undeclared. `compat_error_response` (`gateway/routers/openai_compat.py`)
  envelopes every `StarletteHTTPException` whose path is in `_COMPAT_PATHS`, and the router answers a
  wrong method there with `405`. Live on the rebuilt stack:

  ```
  $ curl -s http://localhost:8000/v1/chat/completions
  405 {"error":{"message":"Method Not Allowed","type":"api_error","code":"internal_error"}}
  ```

  So the body shape is right but the status is undeclared and the `code` says "internal error" for a
  caller mistake — the counterpart of the 403/401 gap the conformance run closed.

The Forge conformance families only send `POST`, so neither fact shows up in the 44/28/24-case runs;
the `400` stays invisible because over-declaring never fails validation.

**Outcome**

`COMPAT_ERRORS` and the document contain only statuses the surface can answer, and `405` is one of them
with a `method_not_allowed` style `code` and `invalid_request_error` type. The document for
`/v1/chat/completions` and `/v1/models` stays derived from the same table, so the drift test keeps
holding, and no runtime behaviour changes beyond the envelope `code`/`type` a wrong-method caller sees.

**Acceptance**

- [ ] `400` is gone from `COMPAT_ERRORS`, from the generated document, and from `_envelope_for`'s fallback
      path if it is only reachable through the default branch
- [ ] A wrong method on `/v1/chat/completions` (and `/v1/models`) answers `405` with the envelope, `type:
      invalid_request_error`, `code: method_not_allowed`, and the document declares that status
- [ ] The existing drift test (`tests/test_openai_compat.py`) covers the new set, so a status in the table
      without a reachable handler — or the reverse — fails CI
- [ ] `uv run pytest tests/test_openai_compat.py tests/test_chat_contract.py -q` and `scripts/gate.sh
      --integration` pass

**Notes**

- Deduplication: grepped `backlog/items/` for `405`, `400`, `openapi`. IDEA-092 (done) built the table
  and the drift test; this is the residual it could not see from the 44-case matrix. IDEA-093 (done) owns
  the auth surface. No item covers 405.
- Verification comment on #161 names `400`, `413`, `429` and `503` as declared but unexercised. `413`,
  `429` and `503` are reachable and already covered by `tests/test_chat.py` (413, 429, 503) and
  `tests/test_openai_compat.py` (429 envelope), so only `400` is a defect; the other three are harness
  coverage, not document error.
- Open question for triage: whether the Forge families should grow cases that exercise `413`, `429` and
  `503` (which need oversized bodies, an exhausted budget and a broken dependency), or whether the pytest
  coverage is the right home and the harness stays happy-path plus auth.
