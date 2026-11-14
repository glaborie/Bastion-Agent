### IDEA-054: Charge inference tokens to a per-principal chat budget

- status: inbox
- priority: P2
- phase: v0.5
- area: gateway
- tags: rate-limiting, redis, chat
- depends-on: -
- spec: ADR-020
- created: 2026-11-14
- updated: 2026-11-14
- source: ADR-020 (Proposed) and THREAT_MODEL.md T12 known gap 3, 2026-11-14

**Problem**

`gateway/rate_limit.py` charges exactly one token per request (the hardcoded
`"1"` cost in `RateLimiter.consume`), so `POST /v1/chat` prices a three-word
question and a 65,536-character prompt with 8,192 output tokens the same. A
principal inside the 120 req/min chat budget has no inference spending bound:
`THREAT_MODEL.md` T12 residual risk still reads "Rate limiting bounds request
rate, not spend", and ADR-020 records the token-budget design but is not
implemented.

**Outcome**

A chat turn reserves `estimated prompt tokens + max_tokens` from
`ratelimit:chat_tokens:<jwt-sub>` before the model is called, is refused with
`429` / `Retry-After` / detail `token budget exhausted` when the reservation does
not fit, and settles the actual `usage` tokens afterwards, including debt when
the estimate was short. ADR-020 moves to `Accepted` and T12 is re-scored against
the live control.

**Acceptance**

- [ ] A turn that exhausts the budget returns `429` with `Retry-After` and detail `token budget exhausted`, and the stubbed router in `tests/test_chat.py` proves `complete()` was never called; a prompt blocked by the injection gate or the egress circuit breaker spends nothing.
- [ ] `uv run pytest tests/test_rate_limit.py tests/test_chat.py -q` passes, and with `REDIS_TEST_URL` set `uv run pytest tests/test_rate_limit_redis.py -q` proves reserve, settle, debt floor at `-capacity` and refill against live Redis.
- [ ] `RATE_LIMIT_CHAT_TOKENS_PER_WINDOW` is a positive-validated setting next to the other `rate_limit_*` fields, `ChatRequest.max_tokens` defaults to 1024 and is always sent upstream, and `grep -rn "rate_limit_chat_tokens_per_window" settings.py gateway/` names both the setting and the consuming route.
- [ ] ADR-020 is `Accepted` with `Last modified` bumped, `CONTROL.md` states the token budget alongside the request budget, and `THREAT_MODEL.md` T12 drops "bounds request rate, not spend" with the score re-derived by `uv run python scripts/recalculate_dread.py`.
- [ ] `scripts/gate.sh` passes.
