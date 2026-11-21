### IDEA-102: Stop attributing client-caused chat failures to the provider

- status: inbox
- priority: P2
- phase: v0.5
- area: agent
- tags: chat, routing, http-errors, tools, observability
- depends-on: -
- spec: ADR-012
- created: 2026-11-20
- updated: 2026-11-20
- source: reporter observed every `tool`-role turn answering `502`; root cause traced in code, not yet reproduced on a live stack

**Problem**

A chat request whose history contains a `tool` turn without the assistant `tool_calls` turn that
produced it is rejected by the upstream model, and the gateway reports that rejection as its own
outage.

`ChatRole = Literal["user", "tool"]` (`gateway/routers/chat.py:108`, accepted by the compat route at
`gateway/routers/openai_compat.py:224`) admits the turn, so nothing at Bastion's boundary refuses or
reshapes a history the model's chat template cannot render. `_client` forwards it, OmniRoute/llama.cpp
answers 4xx, and `UpstreamError` (`agent/routing/client.py:48`, raised at `:339`) inherits
`http_status = 502` / `http_detail = "upstream model unavailable"` from `RoutingError`
(`agent/routing/client.py:44-45`). `gateway/routers/chat.py:684-705` maps that straight through, and
`:685` stamps the model span with `error.type`, so a caller's malformed request is counted as provider
unavailability in both the response and the error metrics. The compat route inherits the same
`502`/`api_error`/`upstream_error` envelope. ADR-012 decision 3 ("Accepted roles", 2026-11-16)
deliberately admits `tool` turns as fenced untrusted data, so the accepted role and the upstream
rejection are inconsistent — this is a defect in a shipped decision, not a decided behaviour.

**Outcome**

A `tool` turn that cannot be forwarded is answered as a caller error, not as provider unavailability:
either refused at the boundary with a `4xx` (amending ADR-012 decision 3's accepted roles) or
translated into a shape the upstream template accepts — one choice, recorded in ADR-012. The
`502`/`upstream model unavailable` path is reserved for genuine upstream failures (IDEA-072's
mapping), and a rejected `tool` turn no longer sets `error.type` on the model span. ADR-026's
definition of `502` and the documented error responses (IDEA-092) move with the change.

**Acceptance**

- [ ] A `tool` turn the upstream cannot render answers `4xx` (or is reshaped and succeeds) instead of
      `502`, asserted by a test that asserts no provider call is made for the refused path
- [ ] An upstream `4xx` is no longer reported as `upstream model unavailable` and no longer sets an
      upstream `error.type` on the model span, asserted by a test on the chat boundary
- [ ] ADR-012 decision 3 records the chosen refuse-or-translate rule, ADR-026's `502` meaning and the
      error responses documented under IDEA-092 match it, and `scripts/gate.sh` passes

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `tool`, `tool_calls`, `502`,
  `UpstreamError`, `upstream model unavailable`. IDEA-092 documents the compat error set (including
  `502`) but does not change its meaning; IDEA-094 picks a status for an unknown model; IDEA-072 pins
  the fail-closed `502`/`503` mapping for real upstream failures; IDEA-073 covers deadlines, retries
  and the breaker; IDEA-049 audits failed tool *executions*, not tool-role chat turns. No item covers
  this. Cross-reference IDEA-092 for the declaration, do not duplicate it.
- Open question for triage: refuse (`4xx`/`422`, which amends the accepted role ADR-012 granted) versus
  translate (reshape the turn so the upstream template accepts it, keeping the role). The refusal is
  the smaller change, the translation keeps clients working; this item does not choose.
- Not reproduced: the reporter's observation plus the code path above say every such `tool` turn
  returns `502`, but the exact rejecting layer (llama.cpp chat template vs OmniRoute validation) was
  not confirmed against a running stack. Reproduce before implementing, per IDEA-073's note style.
- Tests currently only exercise `tool` turns against a stubbed transport
  (`tests/test_egress_model_integration.py` sends user-only), which is why this shipped unseen.
- The generic "any upstream `4xx` becomes `502`" mapping may deserve its own item at triage; this one
  is scoped to the client-caused `tool` turn and its metrics.
