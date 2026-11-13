### IDEA-030: Make the worker reject tool jobs whose identity the gateway did not mint

- status: done
- priority: P1
- phase: v0.3
- area: security
- tags: rbac, redis, hitl, audit, identity
- depends-on: -
- spec: ADR-010
- created: 2026-11-12
- updated: 2026-11-12
- source: security posture review of THREAT_MODEL.md T8 against agent/runtime.py, 2026-11-12

**Problem**

`execute_tool_job` (`agent/runtime.py`) rebuilds `AgentContext` from the ARQ payload, so `actor_id`, `roles` and `tenant_id` are whatever the enqueuer wrote and the worker re-verifies none of them. Anyone who can write the queue can therefore assert any principal, which defeats the four-eyes comparison in ADR-010 decision 3 (a forged `initiator_id` is approved by the real operator) and the tenant boundary ADR-015 decision 4 relies on, because only the cron sweep re-derives the tenant from the stored row — the job path trusts the payload. `THREAT_MODEL.md:228` states the finding and `:100` lists "signed or re-derived identity on queued jobs" as PLANNED, but no backlog item owns it; IDEA-023 raises the cost of writing the queue with mTLS and leaves the payload itself trusted.

**Outcome**

The worker executes a tool job only when it can establish identity without trusting the caller: either the gateway mints a short-lived HMAC over `(job id, actor, roles, tenant, expiry)` that the worker verifies with a key the enqueuer holds and the worker only checks, or the job carries an opaque reference to a gateway-written record whose contents the worker reads. A hand-written job fails closed before any tool runs, before any approval row is written, and before any audit event claims an execution.

**Acceptance**

- [x] A test enqueues a well-formed `execute_tool_job` for a principal the gateway never issued and asserts no `TOOL_EXECUTED` row, no `PendingApproval` row, no tool call, and a rejected-job log or span
- [x] A forged `initiator_id` cannot produce a ticket another approver can satisfy, and a forged `tenant_id` cannot reach another tenant's rows (`tests/test_tool_execution.py`, `tests/test_tenant_isolation.py`)
- [x] Both enqueue sites — the tool-request path and `resume_tool_job` — use the same mint, and the legitimate gateway path still executes end to end
- [x] Expired or replayed payloads are rejected (single use or short TTL), proven by a test that resubmits a captured payload
- [x] `THREAT_MODEL.md` §4 flips the row to LIVE, T8 records the chosen shape and the residual (whoever holds the signing key is still admin), and ADR-010 or a successor records the decision
- [x] `uv run pytest -q`, `ruff check .`, `ruff format --check .`, mypy, pylint and `scripts/gate.sh` pass

**Notes**

- Deduplication: grepped `BACKLOG.md`, `docs/adr/` and `THREAT_MODEL.md` for `opaque`, `forged`, `impersonat`, `signed job`, `re-derive`, `unauthenticated trust boundary`. The only nearby item is IDEA-023 (short-lived mTLS for internal links), whose Notes cite `THREAT_MODEL.md:216` — the TLS half of T8 — and explicitly scope identity out; transport identity leaves any writer who holds a valid client certificate, or the gateway itself, able to forge a principal. ADR-007's demo-console decision relies on the gateway reading `sub` from the session, which is exactly the property the worker never checks. Not a duplicate of IDEA-001 (tenant keys and rows), IDEA-020 (secrets at rest) or IDEA-021 (chain anchoring).
- Classification: `P1`/`v0.3`/`security`. Not `P0`: no live leak, the residual is documented rather than hidden, and exploiting it needs write access the threat model already equates with administrator. `P1` because v0.3 is the multi-tenancy phase (ADR-008) and a payload that names its own tenant makes tenant isolation conditional on Redis ACLs. `area: security` because the deliverable is a trust-boundary invariant; `agent` is the fair alternative, since most lines land in `agent/runtime.py` and `gateway/queue.py`.
- The gap is a design residual, not a coding slip: the threat model already names the remedy. The decision to make is which shape to build (per-job HMAC vs opaque reference) and where the key lives, which needs an ADR line before code because the wrong choice couples four-eyes to a new shared secret.
- Decision taken at implementation (2026-11-12, ADR-018): a per-job HMAC envelope rather than an opaque reference. The reference shape needs a durable pre-enqueue write and would hand the demo CLI database access it does not otherwise use; the envelope reuses the approval-token canonicalisation (`hash_payload`, `canonical_timestamp`) and adds no table. Wire format `v1|<kind>|<sha256 of fields>|<nonce>|<expires_at>`, delivered as `job_nonce`, `job_expires_at`, `job_signature`. The key is `JOB_SIGNING_SECRET`, deliberately separate from `APPROVAL_HMAC_SECRET`, and `_reject_dev_secrets` refuses the documented development value in staging and production. Scope covers `execute_tool_job`, `run_demo_scenario_job` and `resume_tool_job`; the two cron sweeps are in-process calls with no payload.
- Replay is closed by burning the nonce once (`SET job:nonce:<nonce> 1 NX EX <remaining>`), with the TTL measured from the signature deadline rather than arrival. A Redis failure while claiming the nonce is a rejection, not a fall-through.
- A forged payload deliberately writes no audit row: the only identity available is the attacker's, and a hash-chained `SECURITY_INCIDENT` naming an attacker-chosen principal would poison the ledger. The refusal is a structured log line plus a `bastion.job.rejected` span attribute; T8's Verification line points at the tests.
- Test split: `tests/conftest.py` injects a fakeredis nonce store for the suite (the process-wide Redis client would otherwise bind to the first test's event loop, the same hazard the approval-publish stub documents), and `tests/test_job_auth.py::test_a_real_redis_refuses_a_second_claim` covers the real server's `SET NX`/TTL under the `redis_integration` marker.
- Gates: `scripts/gate.sh --integration --evals` → 11/11 passed against a disposable PostgreSQL 16 (`TEST_DATABASE_URL`) and Redis (`REDIS_TEST_URL`): ruff check/format clean, mypy clean (79 files), pylint 10.00/10, pytest 747 passed / 2 skipped (the two `model_integration` probes, no `LLAMA_CPP_BASE_URL`), evals 232/232 with every metric 1.000, and `check_adrs.py`, `validate_rbac.py`, `validate_tool_catalog.py --check`, `check_backlog.py` all OK. The classifier graphs were symlinked into `models/` for the eval run, as on `master`.
