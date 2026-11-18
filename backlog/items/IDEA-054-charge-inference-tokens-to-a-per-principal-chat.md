### IDEA-054: Charge inference tokens to a per-principal chat budget

- status: done
- priority: P2
- phase: v0.5
- area: gateway
- tags: rate-limiting, redis, chat
- depends-on: -
- spec: ADR-020
- created: 2026-11-14
- updated: 2026-11-18
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

- [x] A turn that exhausts the budget returns `429` with `Retry-After` and detail `token budget exhausted`, and the stubbed router in `tests/test_chat.py` proves `complete()` was never called; a prompt blocked by the injection gate or the egress circuit breaker spends nothing.
- [x] `uv run pytest tests/test_rate_limit.py tests/test_chat.py -q` passes, and with `REDIS_TEST_URL` set `uv run pytest tests/test_rate_limit_redis.py -q` proves reserve, settle, debt floor at `-capacity` and refill against live Redis.
- [x] `RATE_LIMIT_CHAT_TOKENS_PER_WINDOW` is a positive-validated setting next to the other `rate_limit_*` fields, `ChatRequest.max_tokens` defaults to 1024 and is always sent upstream, and `grep -rn "rate_limit_chat_tokens_per_window" settings.py gateway/` names both the setting and the consuming route.
- [x] ADR-020 is `Accepted` with `Last modified` bumped, `CONTROL.md` states the token budget alongside the request budget, and `THREAT_MODEL.md` T12 drops "bounds request rate, not spend" with the score re-derived by `uv run python scripts/recalculate_dread.py`.
- [x] `scripts/gate.sh` passes.

**Notes**

- Implemented 2026-11-18. `gateway/rate_limit.py` gained the `chat_tokens` scope, `RateLimiter.reserve`/`settle` (a second Lua script that accepts debt and floors the balance at `-capacity`), `estimate_prompt_tokens` (`ceil(chars / 4)` + 4 per message over the post-DLP, canary-fenced payload) and `settled_tokens` (`total_tokens`, else `prompt_tokens + completion_tokens`, else `None` = charge the reservation). `gateway/routers/chat.py` reserves immediately before `model_router.complete` and settles after it; a refusal is `429` with `Retry-After`, `RateLimit-*` and detail `token budget exhausted`; a settle failure logs and flags `bastion.rate_limit.settle_failed` instead of failing a completed turn. `ChatRequest.max_tokens` defaults to 1024 and is always sent. `RATE_LIMIT_CHAT_TOKENS_PER_WINDOW` (default 100000) sits with the other `rate_limit_*` fields and is positive-validated. ADR-020 is `Accepted`, `CONTROL.md` and `README.md` state the token budget beside the request budget, `.env.example` carries the setting, and THREAT_MODEL T12 drops "bounds request rate, not spend" with the score re-derived 31 → 25 (`recalculate_dread.py --write`).
- Verified: `pytest tests/test_rate_limit.py tests/test_chat.py -q` → 41 passed, 1 skipped (the ONNX-model test, no graphs on this host) against a disposable Postgres; `REDIS_TEST_URL=… pytest tests/test_rate_limit_redis.py -q` → 10 passed against Redis 7, covering reserve, refund, debt, the `-capacity` floor and refill; `scripts/gate.sh` → 13/13 twice. The injection test now asserts a blocked prompt reserves and settles nothing.
- Design point worth keeping: the token budget is skipped when `RATE_LIMIT_ENABLED=false`, so the unit suite keeps testing chat without a Redis store and the two budgets share one switch. The cache hit path spends nothing because the reservation sits inside the model call, which is the only place spend happens.
- Deliberately not done: a per-principal *cost* budget (needs a price table no component owns — still PLANNED in T12), and any per-tenant aggregate. Both are recorded in ADR-020's Consequences rather than silently dropped.
