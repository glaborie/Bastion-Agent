### IDEA-011: Reconcile the CONTROL.md dashboard rate-limit claim with the gateway

- status: done
- priority: P1
- phase: v0.2
- area: docs
- tags: rate-limiting, dashboard, adr, security
- depends-on: -
- spec: ADR-007
- created: 2026-11-10
- updated: 2026-11-10
- source: review of CONTROL.md security considerations against gateway code, 2026-11-10

**Problem**

`CONTROL.md` line 253 lists "**Rate Limiting**: Dashboard API: 60 req/min per user (stricter than chat API)" among shipped security controls, but nothing enforces it: `gateway/main.py` registers only the `security_headers` middleware, `gateway/settings.py` has no rate-limit key, no router returns `429`, and neither `slowapi` nor `limits` is a dependency. ADR-007 decision 7 explicitly defers per-user dashboard rate limiting (60 req/min) to the Phase 1 dashboard features, ADR-008 puts rate limiting in v0.5, and `THREAT_MODEL.md` T12 marks per-principal limits "PLANNED ... None are implemented" — so CONTROL.md is the only document asserting the control exists.

**Outcome**

Either the control exists as CONTROL.md describes it, or CONTROL.md stops describing it as shipped and points at the deferral. Every document agrees on one state, and a reader of CONTROL.md can tell a live control from a planned one without reading the gateway source.

**Acceptance**

- [x] Either (a) the enforcing code exists — the scoped dashboard endpoints are named, the requests-per-window limit is read from a named settings key, an over-limit request produces `429`, and a test in `tests/` proves both the pass-under and fail-over cases — or (b) `CONTROL.md` marks dashboard rate limiting as planned/not implemented and cites ADR-007 decision 7, ADR-008 v0.5 and THREAT_MODEL T12, with no remaining sentence in CONTROL.md claiming the 60 req/min control is shipped
- [x] `grep -rn "60 req/min" .` returns only lines that either qualify the claim as deferred/planned or name the settings key that enforces it
- [x] `uv run python scripts/check_adrs.py` passes, and ADR-007 decision 7 is either left as the deferral or updated in the same change if the limiter shipped — no ADR claims a control that does not exist
- [x] `THREAT_MODEL.md` T12 is consistent with the chosen state: it drops "None are implemented" only when the limiter is real

**Notes**

- `spec: ADR-007` chosen over `-`: decision 7 of the control-dashboard ADR is the recorded decision that owns this control's status (deferred to Phase 1), so the reconciliation is alignment with ADR-007 rather than a greenfield decision. ADR-008 v0.5 and T12 are cited as corroborating scope, not as the governing decision.
- Deduplication: `BACKLOG.md` had no rate-limiting or CONTROL.md item; IDEA-009 (observability ADR) and IDEA-010 (ADR-006 drift) are unrelated and untouched. ADR-007/ADR-008/THREAT_MODEL mention the control only as deferred/planned.
- No implementation and no CONTROL.md edit are part of this intake; this item only records the discrepancy. Triage may split it into "document the deferral" (docs) and "build the limiter" (gateway) if it prefers one state over the either/or acceptance.
- Open question for triage: ADR-007 says Phase 1 dashboard features while ADR-008 lists rate limiting under v0.5; if the limiter is built, which phase owns it needs deciding before the phase field can be tightened.
- 2026-11-10 resolution: took path (a), the limiter was built rather than the claim removed. `gateway/rate_limit.py` implements a Redis token bucket keyed on the JWT subject; the dashboard pages/partials/APIs share `RATE_LIMIT_DASHBOARD_PER_WINDOW` (60) and `POST /v1/chat` uses `RATE_LIMIT_CHAT_PER_WINDOW` (120), both over `RATE_LIMIT_WINDOW_SECONDS` (60). Refusals are `429` with `Retry-After`/`RateLimit-*`; a store outage is `503`. `tests/test_rate_limit.py` covers pass-under, fail-over, scope mapping, HTML rendering and fail-closed; `tests/test_rate_limit_redis.py` proves exhaustion, refill, isolation, concurrency and TTL against live Redis. ADR-013 records the decision, ADR-007 decision 7 and ADR-008 v0.5 were updated, and CONTROL.md/T12 now describe the live control. Phase question answered: it shipped in v0.2, ahead of the v0.5 roadmap line.
