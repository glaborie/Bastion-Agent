### IDEA-094: Return 400 for an unknown compat model

- status: inbox
- priority: P3
- phase: v0.5
- area: gateway
- tags: openai, http-errors, client-compat
- depends-on: -
- spec: ADR-026
- created: 2026-11-20
- updated: 2026-11-20
- source: six-finding OpenAPI review of the compat surface, 2026-11-20

**Problem**

`_alias_is_local` (`gateway/routers/openai_compat.py:188-196`) raises `404` when `model` is not one of
`bastion-auto`, `bastion-local`, or the two configured aliases, with the message "model … is not served
by this gateway". `_envelope_for` maps that to `invalid_request_error` / `code: model_not_found`, and
`tests/test_openai_compat.py:246-255` pins the status.

Two problems with the shape: `404` on an existing route reads as "endpoint missing" to a client that
branches on status, and the declaration in IDEA-092 will advertise a `404` that says the path is gone.
The parameter is wrong, not the route — `400`/`422` is the shape that says so. Either way the behaviour
is undocumented today.

**Outcome**

An unknown `model` on `/v1/chat/completions` answers `400` (or `422`, one choice recorded in ADR-026)
with the same envelope and a code that still says the model is not served, and the document declares it.
A valid alias, the blocked path and the native `/v1/chat` behaviour are unchanged; the native route's own
alias handling is not touched by this item. The pinned test is updated rather than deleted, so the new
status is asserted deliberately.

**Acceptance**

- [ ] A contract test drives `POST /v1/chat/completions` with an unknown `model` and asserts the new status, `error.code` still identifying the model, and that no model call was made (`stub.complete_calls == 0`)
- [ ] The documented response set from IDEA-092 contains the new status, and `tests/test_openai_compat.py` no longer expects `404`
- [ ] ADR-026 decision 3 records the chosen status and why, and `uv run pytest tests/test_openai_compat.py -q` and `scripts/gate.sh` pass

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `model_not_found`, `404`, `unknown model`.
  IDEA-090 (dropped) was about blocked-turn rendering and is not resurrected; IDEA-060 built the route and
  ADR-026 decision 3 is what this amends. No item covers the status.
- Counter-argument for triage, recorded because it decides the item: the OpenAI API itself answers `404`
  `model_not_found` for an unknown model, so the current shape is the compatible one and this item would
  deliberately diverge from the surface it emulates. If triage accepts that, the honest outcome is to drop
  this and document the `404` under IDEA-092 instead.
- `P3` because a client that already handles the envelope loses nothing; the cost is a confusing status.
