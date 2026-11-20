### IDEA-095: Add a usage object to compat chat completions

- status: inbox
- priority: P2
- phase: v0.5
- area: gateway
- tags: openai, tokens, usage, client-compat
- depends-on: -
- spec: ADR-026
- created: 2026-11-20
- updated: 2026-11-20
- source: six-finding OpenAPI review of the compat surface, 2026-11-20

**Problem**

`_completion_body` (`gateway/routers/openai_compat.py:232-259`) emits `id`, `object`, `created`,
`model`, `choices` and the `bastion` extension, and no `usage`. Neither does the chunk stream
(`_synthetic_sse`, `:275-302`). Yet the counts exist one layer down: the settlement path reads
`completion.prompt_tokens`, `completion_tokens` and `total_tokens` (`gateway/routers/chat.py:713-716`)
and the routing client declares them `int | None` (`agent/routing/client.py:200-202`, parsed at
`:541-543`) because a provider may not report them.

An OpenAI-compatible client that reads `response.usage.total_tokens` — the normal way to bill or to
watch a budget — crashes or records nothing. `ChatResponse` (`gateway/routers/chat.py:155-173`) does not
carry the counts either, so this is not only a facade omission: the numbers are consumed for settlement
and then dropped.

**Outcome**

A successful compat completion carries a `usage` object with `prompt_tokens`, `completion_tokens` and
`total_tokens`, sourced from what the provider reported (or the gateway's own estimate where ADR-026
says so), and the streaming replay carries the same object in its final chunk. When the provider reports
nothing, the absence is explicit and documented — omitted or `null`, never a fabricated `0`, because a
zero that means "unknown" corrupts every downstream cost number. ADR-026 records which of the three
sources is authoritative and the blocked-turn case, where no model call happened at all.

**Acceptance**

- [ ] A contract test drives a provider that reports usage and asserts all three integers in the compat body, and that they equal what settlement recorded for the same turn
- [ ] A test drives a provider that reports none and asserts the documented absence rather than zeros, with the choice named in ADR-026
- [ ] The `stream: true` replay carries `usage` in its terminal chunk and remains `[DONE]`-terminated with no model text
- [ ] ADR-026 decision 4 documents the object, its source and the absent case; `uv run pytest tests/test_openai_compat.py tests/test_chat.py -q` and `scripts/gate.sh` pass

**Notes**

- Deduplication: grepped `backlog/items/` and `docs/adr/` for `usage`, `tokens`, `total_tokens`.
  IDEA-054 and IDEA-028 consume provider counts for the token budget but never expose them; ADR-008 notes
  that token and cost budgets remain open. IDEA-092 and IDEA-097 document the same payload and are
  complementary. No item was merged.
- This is the only finding of the six that adds a field rather than describing one, which is why it is P2:
  the absence is a real gap for any downstream accountant, and it contradicts the surface's purpose.
- Open questions for triage: whether `usage` also appears on the blocked turn (no model call, so the
  estimate is the only number, and reporting it may invite billing for nothing); whether `ChatResponse`
  grows the counts so native `/v1/chat` can answer the same question.
