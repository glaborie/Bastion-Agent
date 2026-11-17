### IDEA-066: Prove the gateway's fail-closed contract with a deterministic fault-injection suite

- status: inbox
- priority: P2
- phase: v0.5
- area: gateway
- tags: testing, chaos, resilience, latency, ci
- depends-on: -
- spec: ADR-004
- created: 2026-11-17
- updated: 2026-11-17
- source: session request on 2026-11-17 ("chaos engineering to stress test the gateway with delays, latency, broken endpoints")

**Problem**

The fail-closed contract is asserted one stage at a time and never as a whole. `tests/test_chat.py:424` covers a DLP failure, `:484` a PII route failure and `:382` a canary leak; `tests/test_routing_client.py:245-311` covers retryable and non-retryable statuses and the no-cloud-fallback rule; `tests/test_egress_redis.py` covers the quarantine breaker. Nothing exercises the paths a latency spike or a dead dependency actually takes: `httpx.TimeoutException` (`agent/routing/client.py:164`) has no test, nor does a database failure inside `_record` (`gateway/routers/chat.py:229`), an egress sanitizer outage through the chat endpoint (`:638`), a rate-limiter outage through the endpoint (`gateway/rate_limit.py:140`) or a classifier exception at request time. The tree has no chaos, load or fault-injection tooling at all (`grep -rin "chaos|toxiproxy|k6|locust"` finds nothing), so a regression that delivers an answer without its audit row, or that retries a confidential prompt onto another alias, can pass the gate.

**Outcome**

One merge-blocking pytest module drives `POST /v1/chat` with a fault injected at each dependency boundary and asserts the whole outcome, not only the status code: the mapped `502`/`503`, no model answer delivered, exactly one terminal audit row for the failed stage, the attempt count bounded by `OMNIROUTE_MAX_RETRIES`, and the route unchanged for `CONFIDENTIAL`/PII traffic. It runs in the existing pytest job with no container, no new dependency and no real 120-second wait.

**Acceptance**

- [ ] `tests/test_failure_modes.py` injects a timeout, a 500/429, a connection reset and a slow body at the `httpx` transport, and asserts `502`/`503`, `attempts == max_retries + 1`, and that no answer is returned
- [ ] A PII-bearing turn whose local route fails returns `503` with the `pii_route_local_unavailable` audit row, and the transport records no request to `cloud-primary`
- [ ] A Redis limiter outage, an egress sanitizer outage and a classifier exception each return `503` from `/v1/chat` and leave no `RESPONSE_SENT` row
- [ ] A database failure during an intermediate `_record` returns a 5xx, leaves no `RESPONSE_SENT` row and delivers no answer
- [ ] The suite uses short configured timeouts and a fake clock, so the module finishes in seconds and needs no Toxiproxy, Redis or Postgres container
- [ ] `docs/TROUBLESHOOTING.md` maps each injected fault to the status a caller sees, and `scripts/gate.sh` stays green

**Notes**

- Deduplication: grepped `backlog/items/`, `docs/adr/` and `scripts/` for `chaos`, `toxiproxy`, `k6`, `locust`, `load test`, `fault`, `failure mode`, `deadline`, `bulkhead` and `circuit breaker`. IDEA-039 is uptime monitoring, IDEA-022 is Falco runtime detection, IDEA-049 is failed tool-call audit, IDEA-065 is handoff notification, and ADR-004 decision 4 already records retries and fail-closed. None covers a fault-injection suite.
- `spec: ADR-004` names the decision the suite protects (same-alias retries, no confidential fallback); the DLP, egress and limiter stages are governed by ADR-002, ADR-012 and ADR-013 and are exercised rather than changed.
- This is the cheap first step before a live harness: a Toxiproxy `chaos` profile (network-level latency and reset between gateway and OmniRoute/Redis/DB) is a separate item because it adds a service, an image pin, a Trivy inventory entry and an ADR under ADR-016, and it tests the same contract more faithfully at much higher cost.
- Classification: `P2`/`v0.5`. Nothing is broken today and the shipped unit tests cover each stage in isolation, so not `P0`/`P1`; ADR-008 v0.4 is adaptive policy and v0.5 is production readiness, the nearest home for resilience proof. Triage may pull it into v0.4 if the chaos work is wanted now.
- Intake only: no test, source, config or document change is part of this capture.
