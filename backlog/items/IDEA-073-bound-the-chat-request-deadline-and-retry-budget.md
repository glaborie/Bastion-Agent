### IDEA-073: Bound the chat request deadline and retry budget under upstream latency

- status: inbox
- priority: P2
- phase: v0.5
- area: agent
- tags: latency, routing, resilience, timeout, circuit-breaker
- depends-on: -
- spec: ADR-004
- created: 2026-11-17
- updated: 2026-11-17
- source: session request on 2026-11-17 ("chaos engineering to stress test the gateway with delays, latency, broken endpoints")

**Problem**

A slow upstream has no budget. `agent/routing/client.py:106` sets a `120 s` timeout, `max_retries=1` and a `0.25 s` backoff, so one hung completion can occupy a request for roughly 240 seconds; the worker's `job_timeout` is 300 seconds (`agent/runtime.py:638`), and DLP, classification and the egress stage add time on top of the model call. The gateway sets no request deadline, so the timeout is the only bound and it is per attempt, not per turn. The only circuit breaker in the tree is the egress quarantine (`agent/egress/sanitizer.py:98`), a disclosure control keyed by session, not an availability breaker for OmniRoute or `llama.cpp`. A latency spike therefore consumes the whole worker budget, queues later turns and turns a slow model into an outage; ADR-004 decision 4 records retries and fail-closed behaviour but no deadline, bulkhead or availability breaker.

**Outcome**

One turn is bounded end to end by a configurable deadline checked between stages and before each retry, the retry budget is derived from the time that remains rather than a fixed count, and a per-route concurrency limit plus an availability breaker stop a hung route from consuming the worker. `CONFIDENTIAL` and PII-bearing prompts still never switch alias, and the worst-case turn completes below `JOB_TIMEOUT` with a `503`/`504` instead of holding a worker.

**Acceptance**

- [ ] `REQUEST_DEADLINE_SECONDS` (default below `JOB_TIMEOUT`) is set at the chat boundary, checked before each stage and before each retry, and a test with a fake clock proves a hung upstream returns `503`/`504` at the deadline, not after `OMNIROUTE_TIMEOUT_SECONDS * (max_retries + 1)`
- [ ] The retry budget is the remaining deadline: a test proves a request with little time left makes zero retries, and `OMNIROUTE_MAX_RETRIES` still bounds the count
- [ ] A per-route bulkhead rejects the `N+1` concurrent call to a hung route immediately, and the local and cloud counters are separate
- [ ] An availability breaker opens after `N` consecutive timeouts/5xx on a route, fails the next call fast with `503`, and half-opens after the cooldown; a test covers open → half-open → closed
- [ ] `tests/test_routing_client.py::test_confidential_traffic_never_falls_back_to_cloud` and the PII fail-closed test still pass unchanged: a breaker never moves a confidential prompt to another alias
- [ ] New settings are in `.env.example` with defaults and validators, `docs/TROUBLESHOOTING.md` explains the fast-fail response, ADR-004 is amended or superseded in the same change, and `uv run python scripts/check_adrs.py` passes
- [ ] `scripts/gate.sh` is green

**Notes**

- Deduplication: grepped the backlog and ADRs for `deadline`, `bulkhead`, `circuit breaker`, `retry budget`, `timeout` and `latency`. IDEA-003 is classifier GPU latency, IDEA-011 is a dashboard rate-limit claim, IDEA-028 is model tiering and IDEA-039 is uptime monitoring; none bounds a chat turn. ADR-004 decision 4 names retries and health checks but sets no budget.
- The deadline is the cheap half and the breaker is the expensive half; if triage wants a smaller first step, the deadline plus retry budget can land alone and the bulkhead/breaker split into a follow-up.
- Classification: `P2`/`v0.5`. No incident has been observed; this is a production-readiness gap under latency, and ADR-008 v0.5 is the nearest home. It is not `P0`/`P1` because the stack currently returns an error rather than leaking or corrupting the ledger.
- Intake only: no source, config, test or ADR change is part of this capture.
