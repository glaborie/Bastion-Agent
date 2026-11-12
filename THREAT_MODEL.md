# THREAT_MODEL.md

Bastion-Agent threat model

- Version: 2.3
- Last updated: 2026-11-11
- Reviewed against: commit `fa655d6`
- Author: Guillaume Laborie
- Status: working document for a portfolio project. It is not a compliance attestation and has not been independently reviewed.

## 1. How to read this document

Every control carries one of three statuses. They describe the repository, not the target architecture.

| Status | Meaning |
|---|---|
| LIVE | Implemented in code, with a test module in `tests/`. |
| PARTIAL | Implemented in part, or implemented but not enforced at runtime or in CI. The gap is stated. |
| PLANNED | Described in an ADR or in `SECURITY.md`, but not implemented. |

"LIVE" means the code path exists and has tests. It does not mean the control is unbreakable. Each threat lists its residual risk.

Framework references:

- OWASP Top 10 for LLM Applications, 2026 edition (IDs written `LLM01:2026`).
- OWASP Top 10 for Agentic Applications 2026 (IDs `ASI01` to `ASI10`).
- MITRE ATLAS technique IDs (`AML.T####`).

These IDs were checked against secondary sources in November 2026. Check them against the official OWASP GenAI Security Project and MITRE ATLAS pages before quoting them in a customer document, because the OWASP LLM list was reordered in 2026 and older articles use the 2025 numbering.

## 2. Scope and assumptions

In scope: the FastAPI gateway, the ARQ worker, PostgreSQL audit ledger, Redis (vault, canary, quarantine, queue), Keycloak OIDC integration, OmniRoute model routing, the ONNX classifiers and the Presidio DLP stage.

Assumptions:

- One deployment may serve multiple tenants. Tenant isolation is scoped by ADR-015: Redis keys carry a tenant segment, `audit_logs` and `pending_approvals` carry `tenant_id`, and request-path reads require the authenticated tenant. PostgreSQL row-level security remains planned for the rest of v0.3.
- The host, container runtime, network segmentation, Keycloak hardening and secret management are the deployer's responsibility. The repository ships development defaults only (`.env.example`, the Keycloak realm export, shared demo passwords).
- The model is untrusted. No security decision depends on model output or model instructions.

Out of scope:

- Factual accuracy of model answers (`LLM07:2026` Misinformation). The platform does not verify content. Human approval applies to state-changing tools only.
- An attacker with PostgreSQL superuser or host root access (see T10 for the audit-ledger consequence).
- Legal interpretation. `COMPLIANCE.md` and `README-SWISS.md` map controls to requirements. They do not claim that a deployment is compliant.

## 3. Architecture and trust boundaries

Chat path. `POST /v1/chat` is the only route that reaches a model.

```
client
  -> Keycloak JWT or session cookie + RBAC (operator, analyst, admin) + CSRF   [boundary 1]
  -> audit INPUT_RECEIVED (request hash only)
  -> Presidio DLP + reversible vault (Redis)                                   [boundary 2]
  -> classifier ensemble on the RAW text (injection guard + safety guard)
  -> injection detected: refuse before inference (gateway notice, no model call)
  -> route: local llama.cpp (confidential) | cloud (public)                    [boundary 3]
  -> system prompt gets session canary; role=tool turns are fenced
  -> model via OmniRoute
  -> egress inspection (canary scan, quarantine) -> token restore              [boundary 4]
  -> audit EGRESS_FILTERED, RESPONSE_SENT; SECURITY_INCIDENT on block
```

Tool path. Separate from chat.

```
authenticated caller -> ARQ job execute_tool_job -> request_tool_execution
  -> RBAC check (denials audited)
  -> read_only tool: execute
  -> mutating tool: PendingApproval bound to the exact arguments
       -> approver != initiator -> resume_tool_job -> EXECUTED
       -> reject / expire -> terminal
  every transition appends a hash-chained audit record in the same transaction
```

Two facts shape the model:

1. In the current build the chat endpoint returns text only. Nothing parses model output into tool calls. Tool execution is requested by an authenticated caller through the queue, not by the model. Model-driven tool misuse therefore becomes an in-scope threat only when an agent loop is added (see T7).
2. A confidential or injected prompt is routed to the local model, not rejected. This contains data egress. It does not stop the local model from reading the prompt (see T1).

## 4. Control status summary

| Control | Status | Where |
|---|---|---|
| OIDC JWT validation, declarative RBAC, CSRF for sessions | LIVE | `gateway/auth/` |
| Two-stage DLP, reversible AES-256-GCM vault | LIVE | `agent/dlp/` |
| Classifier ensemble, fail-closed to CONFIDENTIAL | LIVE (needs ONNX graphs) | `agent/routing/classifier.py` |
| Canary tripwire, quarantine, untrusted-content fencing | LIVE | `agent/egress/sanitizer.py` |
| Hash-chained audit ledger and verification | LIVE | `db/audit.py`, `/api/audit/verify` |
| Four-eyes approval state machine | LIVE | `agent/tools/execution.py` |
| Tool catalog allow-list (`docs/tools/v1.json`) | LIVE | runtime filtering, startup drift check, `-32003` |
| Dependency audit against OSV and Trivy image scan with SBOM | LIVE | `supply-chain` job, ADR-016 |
| Runtime syscall detection (Falco, opt-in `security` profile) | PARTIAL | `config/falco/`, ADR-017 |
| Test and eval gate in CI | PLANNED | CI runs pylint with `--exit-zero` only |
| Kill-switch tiers | PLANNED | ADR-009 only |
| Per-principal request rate limits (`dashboard` 60/min, `chat` 120/min) | LIVE | `gateway/rate_limit.py`, ADR-013 |
| Runtime syscall detection (Falco, opt-in `security` profile) | PARTIAL | `config/falco/`, ADR-017 |
| Per-principal token and cost budgets | PLANNED | none found |
| Signed job payloads for every identity-bearing enqueue (`execute_tool_job`, `run_demo_scenario_job`, `resume_tool_job`) | LIVE (host key access is still admin) | `agent/job_auth.py`, `agent/runtime.py`, ADR-018 |
| East-west mTLS for PostgreSQL, Redis and Keycloak (opt-in `pki` profile) | LIVE (profile-scoped; host root still wins) | `docker-compose.pki.yml`, `docs/PKI.md`, ADR-019 |
| External anchoring of the audit chain | PLANNED | see T10 |
| Langfuse and Phoenix exporters | PLANNED | collector ships with the `debug` exporter |

Runtime detection is the only control in this table that is not started by the default
`docker compose up`: Falco runs privileged, so it is opt-in and confined to the `security`
profile. On a Docker Desktop host the syscall rules fire but `/proc` metadata (`proc.cmdline`,
`proc.pname`) can be unavailable, so the data-container healthcheck exceptions are effective
on a native Linux host only. The residual is that the detector observes and does not contain,
and a host-root attacker can stop it.

Runtime detection is opt-in: `docker compose --profile security up -d falco` starts one privileged container that watches the stack's syscalls and writes JSON alerts to `artifacts/falco/events.json`. It is a witness, not containment: there is no kill, quarantine, paging or SIEM integration, and the container can be stopped by anyone who controls the host. On Docker Desktop the syscall rules work but `/proc` metadata can be unavailable, so allowlist entries that depend on `proc.cmdline` are ineffective there; the control is fully verifiable on a native Linux host.

## 5. Threats

### T1. Direct prompt injection and jailbreak

- References: `LLM01:2026`, `ASI01`, `AML.T0051.000`, `AML.T0054`
- Attack: a user crafts input that overrides instructions or extracts data.
- Controls:
  - LIVE: injection guard evaluated first in the classifier ensemble (ADR-011). A positive result labels the prompt CONFIDENTIAL, so it never reaches a cloud provider.
  - LIVE: a detected injection is refused before the model is called. The caller gets HTTP 200 with `blocked: true` and a gateway-authored notice, `EGRESS_FILTERED` records `blocked: true`/`prompt_injection`, and `SECURITY_INCIDENT` records the routing-stage verdict. No model answer exists to fabricate a system prompt from (ADR-012 decision 10).
  - LIVE: the classifier fails closed. A missing graph, session error, malformed output or digest mismatch resolves to CONFIDENTIAL.
  - LIVE: the canary tripwire catches a successful instruction override that leaks the marker (T3).
  - LIVE: no authorization decision depends on model output.
- Residual risk:
  - A false positive is refused rather than answered: a benign prompt-engineering discussion at or above `0.662` is treated as hostile. The threshold is calibrated on a 32-row benign set, not held-out recall.
  - The deterministic fallback classifier (`ENVIRONMENT=local` only) cannot detect injection. Non-local deployments without the ONNX models refuse to start.
  - The golden set has 10 injection cases. That is a regression check, not a recall estimate.
- Verification: `tests/test_classifier.py`, `tests/test_classifier_evals.py`, `tests/test_chat.py`, `tests/test_delivered_escrow.py`, `tests/data/goldens.jsonl`.

### T2. Indirect prompt injection through tool or retrieved content

- References: `LLM01:2026`, `ASI01`, `AML.T0051.001`
- Attack: instructions hidden in tool output or retrieved documents.
- Controls:
  - LIVE: content in `role: tool` turns is wrapped in `<untrusted_content source="...">`. Embedded fence tags are neutralised so a payload cannot close the fence. The `source` attribute is sanitised.
  - LIVE: the classifier scans all turns, including tool turns, on the raw text.
  - LIVE: a detected indirect injection is refused before inference by the same gate as T1 (ADR-012 decision 10); no model answer is produced.
  - LIVE: canary tripwire as in T3.
- Residual risk:
  - Fencing is a structural signal, not a guarantee. A model can still choose to obey fenced text (stated in ADR-012).
  - The gateway trusts the caller to label retrieved content as `role: tool`. Untrusted text sent in a `user` turn is not fenced.
  - There is no retrieval pipeline in this repository. Indirect injection arrives only through caller-supplied tool turns.
- Verification: `tests/test_egress_sanitizer.py`, `tests/test_egress_evals.py`.

### T3. System-prompt and hidden-context extraction

- References: `LLM08:2026` (Hidden Context Exposure), `AML.T0056`
- Attack: the user coaxes the model into revealing its instructions.
- Controls:
  - LIVE: one `BASTION-CANARY-<uuid4>` per vault session. It is random, not derived from the session id.
  - LIVE: the output scan matches any token with the configured prefix, not only the current session's value. A hit discards the response, writes a `SECURITY_INCIDENT` and quarantines the session (default 900 s). The quarantine check runs before the next inference call.
  - LIVE: an answer that claims to disclose its instructions ("here is the system prompt", "my instructions are", "I was instructed to") is recorded as `disclosure_claim` on `EGRESS_FILTERED` and on the span, and is still delivered. The claim may be fabricated; it is a verdict, not a block (ADR-012 decision 9).
  - LIVE: if the injection guard fired, the turn was already refused before inference (ADR-012 decision 10), so a direct extraction attempt produces no model answer to fabricate from.
  - LIVE: if Redis is unreachable the gateway returns 503. It never delivers an unscanned response.
- Residual risk: the canary detects verbatim leakage only, and the claim detector names a sentence that admits to disclosure rather than proving one. A silent paraphrase, a partial extraction or a rewritten instruction is not detected by either control. The system prompt contains no secrets by design, which limits the impact; the trust harm of a fabricated disclosure (a caller is told a disclosure happened) is now visible in the ledger instead of unflagged.
- Verification: `tests/test_egress_sanitizer.py`, `tests/test_chat.py`.

### T4. Sensitive data disclosure to a cloud model or in responses

- References: `LLM02:2026`, `AML.T0057`
- Attack: PII or secrets in prompts reach an external provider, or are echoed in output.
- Controls:
  - LIVE: Presidio replaces entities with `{{ENTITY:TYPE_N}}` markers before inference. Default entity list: PERSON, EMAIL_ADDRESS, PHONE_NUMBER, IBAN_CODE, IP_ADDRESS, CREDIT_CARD, US_SSN, plus four local shape recognizers: API_KEY (provider token formats and secret assignments), ADDRESS (street + postal code + place), DATE_OF_BIRTH (a date with an explicit birth anchor) and AHV_NUMBER (a Swiss AHV/AVS number, checksum-validated). Presidio's generic LOCATION/DATE_TIME are deliberately not enabled; they label benign text as PII (ADR-002 decision 5).
  - LIVE: the vault stores values as AES-256-GCM ciphertext in Redis. The AAD binds each ciphertext to its session and token. A 30-minute TTL applies.
  - LIVE: routing classifies the raw text, so redaction cannot weaken the verdict. Confidential prompts go to the local model.
  - LIVE: the audit ledger stores a hash of the request, never prompt text or tool argument values.
  - LIVE: any DLP failure returns 503. Detected entities are always tokenised, and a prompt in which DLP found personal data is kept on the local model even when the classifier says PUBLIC, so incomplete recall does not send it to a third party (ADR-002 decision 5). A local-model failure on such a prompt returns 503 with a SECURITY_INCIDENT.
- Residual risk:
  - Presidio detects patterns and named entities. It does not detect confidential business content without identifiers. That is the classifier's job, and it is probabilistic.
  - DLP recall is bounded by the entity list and one English NER model. A name outside `en_core_web_sm`'s vocabulary is not redacted; it reaches the local model in plaintext (not a third party, because any detected entity forces the local route). A prompt whose only personal data is such a name still takes the classifier's route.
  - The AHV/AVS recognizer validates the EAN-13 check digit, but `756` is also Switzerland's GS1 prefix: a Swiss product barcode of the same shape is checksum-valid and is redacted too. Other Swiss identifiers (UID/CHE company number, postal account numbers) still have no recognizer.
  - The vault key and HMAC secrets come from the environment. Defaults in `.env.example` are development values. A production deployment needs a secret manager and rotation, which are not implemented.
  - Restored plaintext is returned to the caller by design.
- Verification: `tests/test_dlp_presidio.py`, `tests/test_dlp_evals.py`, `tests/test_vault.py`.

### T5. Cross-session decoding of vault tokens

- References: `LLM02:2026`, `ASI03`
- Attack: a caller reuses another principal's conversation id to restore their tokens.
- Controls:
  - LIVE: vault session = `sha256(actor_id + "\0" + conversation_id)`. The actor is bound in, so the same conversation id under two principals resolves to different sessions.
  - LIVE: AAD binding makes a ciphertext copied across sessions fail authentication.
  - LIVE: an expired marker is left visible and counted. It is never guessed.
- Residual risk: one deployment-wide AES key still protects every tenant's vault; isolation comes from the tenant namespace and the AAD binding, so a ciphertext copied across tenants fails authentication. PostgreSQL RLS is not yet enabled.
- Verification: `tests/test_vault.py`, `tests/test_chat_contract.py`, `tests/test_tenant_isolation.py`.

### T6. Identity, session and privilege abuse at the gateway

- References: `ASI03`, `LLM03:2026`
- Attack: forged or stolen tokens, CSRF against the dashboard, role escalation.
- Controls:
  - LIVE: RS256/ES256 JWT validation against a cached JWKS. The audit identity is the `sub` claim.
  - LIVE: `require_roles` is the single authorization primitive. `admin` is a superset, applied in one place.
  - LIVE: dashboard sessions are opaque cookies with a CSRF token on mutating requests.
- Residual risk:
  - The shipped Keycloak realm uses shared development passwords and must not be exposed.
  - ADR-009 describes time-bound, sponsored operator roles. That is not a runtime control in this repository.
- Verification: `tests/test_auth_oidc.py`, `tests/test_auth_session.py`, `tests/test_rbac.py`.

### T7. Tool misuse and unauthorized state change

- References: `LLM03:2026` (Excessive Agency), `ASI02`, `AML.T0053`
- Attack: a tool is invoked outside its intended scope, or a mutating action runs without oversight.
- Controls:
  - LIVE: tools are declared with `@tool(read_only, required_role)`. Handler signatures are checked at import time. Arguments are validated against JSON types, with a size cap.
  - LIVE: RBAC is checked per call. Denials are written to the ledger.
  - LIVE: mutating tools suspend into a `PendingApproval` bound to the exact arguments (see T9).
  - LIVE: built-in file tools reject absolute paths, `..` traversal and symlink escapes, cap reads and writes, and write atomically.
  - LIVE: Gate 1 catalog. `available_tools()` — the model-facing list — returns
    only definitions approved by `docs/tools/v1.json`; `request_tool_execution()`
    re-checks the catalog before argument validation, RBAC or ticket creation and
    rejects anything else with `-32003`. An unreadable catalog exposes no tools,
    gateway and worker startup fail on registry drift, and an approved ticket
    whose tool left the catalog is marked `FAILED` with a `SECURITY_INCIDENT`.
  - PLANNED: kill-switch tiers and autonomy budgets (ADR-009).
- Residual risk: when an agent loop is added, the model becomes a source of tool
  requests. The loop must carry the end user's identity into `AgentContext`, not
  a service identity; Gate 1 is already enforced at the execution boundary.
- Verification: `tests/test_tool_catalog.py`, `tests/test_tool_decorator.py`,
  `tests/test_tool_execution.py`, `tests/test_rbac.py`,
  `scripts/validate_tool_catalog.py --check`.

### T8. The job queue as an unauthenticated trust boundary

- References: `ASI03`, `LLM03:2026`
- Attack: a party with write access to the ARQ Redis queue enqueues `execute_tool_job` with a chosen `actor_id` and `roles`.
- Finding: the queue was an unauthenticated trust boundary. `execute_tool_job` rebuilt `AgentContext` from job arguments and the worker re-verified neither the identity nor the roles, so anyone who could write the queue could assert any principal; a forged initiator also weakened the four-eyes rule, and a forged tenant crossed ADR-015's boundary.
- Controls:
  - LIVE: every identity-bearing job carries an HMAC-SHA256 envelope over the exact field map (`agent/job_auth.py`, ADR-018). The worker verifies it in constant time before the guard runs, so an unsigned or tampered payload returns `unauthorized_job` and produces no tool call, no ticket and no ledger row.
  - LIVE: the envelope nonce is burned once with `SET NX EX`, so a captured payload cannot be replayed; the TTL is measured from the signature deadline.
  - LIVE: the signing key is `JOB_SIGNING_SECRET`, separate from `APPROVAL_HMAC_SECRET`, and `_reject_dev_secrets` refuses the development value in staging and production.
  - LIVE (profile-scoped): the opt-in `pki` profile puts TLS and per-service client certificates in front of PostgreSQL, Redis and Keycloak, so a shared password no longer authenticates east-west and Redis has no plaintext port. `docs/PKI.md` records the refusal cases; ADR-019 records the limit.
  - PLANNED: separate Redis ACL users for gateway and worker, and no host port exposure. The development compose file still publishes Redis on a loopback port for the demo.
  - PLANNED: OmniRoute and the OTLP endpoint stay plain HTTP under the `pki` profile, and `pgadmin`/`redis-ui` are excluded because they cannot present a client certificate.
- Residual risk: whoever holds `JOB_SIGNING_SECRET` — host root, the `.env`, anything that can read the gateway environment — can mint any identity. The control moves the threshold from "write Redis" to "write Redis and hold the key"; it does not defend against a host attacker, and the key has no rotation schedule or version tag.
- Verification: `tests/test_job_auth.py` (unsigned, tampered, cross-tenant, replayed and minted payloads), `tests/test_tool_execution.py` (the signed gateway path still executes), ADR-018.

### T9. Approval workflow abuse

- References: `ASI02`, `ASI03`
- Attack: self-approval, replay of an approval, approval of a changed action, collusion, stale tickets.
- Controls:
  - LIVE: `approver_id` must differ from `initiator_id`.
  - LIVE: the ticket is bound to a fingerprint of the exact arguments. The capability token is HMAC-signed, stored hashed, single-use and expiring.
  - LIVE: resume is idempotent. Expired tickets are closed by a sweep (at most 30 s lag).
  - LIVE: every transition writes an audit record in the same transaction as the state change.
- Residual risk: two colluding operators, or one person controlling two accounts, defeats four-eyes. Approval fatigue is not mitigated. There is no risk tiering of approvals. Identity proofing is the deployer's responsibility.
- Verification: `tests/test_approvals.py`, `tests/test_tool_execution.py`.

### T10. Audit tampering and repudiation

- References: accountability control. No direct OWASP LLM entry.
- Attack: an insider edits or deletes ledger rows to hide an action.
- Controls:
  - LIVE: each record hashes its content plus the previous record's hash (SHA-256). Each stage commits independently, so evidence survives a later failure.
  - LIVE: `POST /api/audit/verify` and `scripts/verify_audit_chain.py` recompute the chain.
  - LIVE: payloads are stored as hashes in `audit_logs`. Argument values and prompt text never enter the ledger.
  - OPTIONAL, pre-production only: with `PAYLOAD_ESCROW_ENABLED=true`, `INPUT_RECEIVED` also writes the exact payload it hashed to the separate `payload_escrow` table as AES-256-GCM ciphertext (per-record nonce, AAD bound to the audit id, `payload_hash`, tenant and kind). A read is `admin`-only, requires an explicit `POST /api/audit/{record_id}/escrow`, and appends `ESCROW_ACCESSED`. Rows expire on `PAYLOAD_ESCROW_TTL_SECONDS` (24 h) and are hard-deleted; production refuses to start with the flag on.
- Residual risk:
  - A chain inside the same database detects partial edits. An attacker with write access can recompute the whole chain. Detecting that needs the head hash exported to a separate system or write-once store, plus an INSERT-only database role. Neither is implemented.
  - When escrow is enabled, `payload_escrow` is a recoverable PII store: someone holding both the process key and the database can decrypt prompts for the retention window. That is the accepted trade of a debugging build, not a production posture; the ledger and its chain are unchanged either way.
- Verification: `tests/test_audit_chain.py`, `tests/test_payload_escrow.py`.

### T11. Supply chain and model-artifact tampering

- References: `LLM04:2026`, `LLM05:2026`, `ASI04`, `AML.T0010`
- Attack: a vulnerable dependency, a swapped classifier model, a poisoned container image.
- Controls:
  - LIVE: classifier ONNX graphs are digest-checked. A mismatch fails closed to CONFIDENTIAL.
  - LIVE: `scripts/update_threat_intel.py` queries every package in `uv.lock` against OSV and exits non-zero on unignored findings. The `supply-chain` job runs it on every push and pull request.
  - LIVE: `scripts/scan_images.sh` exports every image the compose stack ships, scans the archives with the digest-pinned Trivy service (no Docker engine socket), writes a CycloneDX SBOM and a Trivy CVE report to `artifacts/compliance/<date>/`, and fails on an unsuppressed CRITICAL. `trivy.yaml` is the only suppression path: every entry names the image scope, a justification and an expiry date. The same command runs in the `supply-chain` job and its output is uploaded as the `compliance-reports` artifact (ADR-016).
  - LIVE: GitHub Actions are pinned by commit SHA.
  - PARTIAL: image signing and verification (cosign), and IaC or secret scanning. `OMNIROUTE_IMAGE` and `LLAMA_CPP_IMAGE` are digest-pinned by default but can be overridden with a tag-only reference from `.env`; the accepted CRITICALs for Postgres and RedisInsight are image-scoped and expiring in `trivy.yaml`.
- Residual risk: the LLM served through OmniRoute and llama.cpp is not integrity-checked by this project. The registry and the scanner image are trusted by digest, so a compromised tag or registry could scan clean; the SBOM is only as complete as Trivy's package discovery for the scanned base images.

### T12. Resource exhaustion and denial of service

- References: `LLM06:2026` (Unbounded Consumption), `AML.T0029`
- Attack: oversized or repeated requests, runaway token spend.
- Controls:
  - LIVE: at most 64 messages, 32,768 characters per message, 65,536 in total, `max_tokens` at most 8192. A tool argument size cap applies.
  - LIVE: a quarantined session cannot continue to consume inference.
  - LIVE: a per-principal Redis token bucket bounds request rate — 60 requests per 60 s for the dashboard and its polling APIs, 120 per 60 s for chat — and refuses with `429` plus `Retry-After`. A limiter outage is `503`, never unlimited (ADR-013).
  - PLANNED: per-principal token and cost budgets. A principal can still spend its full request allowance on expensive turns.
- Residual risk: fail-closed design is a deliberate trade. An outage of Presidio, Redis or the classifier denies service instead of degrading security. Rate limiting bounds request rate, not spend, so the T12 score is unchanged until token and cost budgets exist.

## 6. Risk scoring

Scores are the author's estimates of residual risk with the controls as they exist in the repository today, 1 to 10 per factor, total is the sum. They are a prioritisation aid, not a measurement. `scripts/recalculate_dread.py --check` keeps the totals and the priority list consistent with the factors.

### DREAD Scoring

| Threat | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | **Total Score** |
|--------|------------------|-----------------|----------------|----------------|----------------|-----------------|
| **T1 Direct prompt injection** | 5 | 7 | 6 | 5 | 8 | **31** |
| **T2 Indirect prompt injection** | 5 | 6 | 5 | 5 | 6 | **27** |
| **T3 Hidden-context extraction** | 3 | 6 | 6 | 4 | 7 | **26** |
| **T4 Sensitive data disclosure** | 8 | 6 | 5 | 7 | 6 | **32** |
| **T5 Cross-session vault decoding** | 7 | 3 | 3 | 4 | 3 | **20** |
| **T6 Gateway identity and privilege abuse** | 8 | 4 | 4 | 7 | 5 | **28** |
| **T7 Tool misuse and unauthorized change** | 7 | 4 | 3 | 5 | 4 | **23** |
| **T8 Job queue trust boundary** | 9 | 9 | 4 | 8 | 4 | **34** |
| **T9 Approval workflow abuse** | 7 | 5 | 4 | 4 | 4 | **24** |
| **T10 Audit tampering** | 7 | 5 | 3 | 6 | 4 | **25** |
| **T11 Supply chain and model artifacts** | 8 | 3 | 3 | 8 | 5 | **27** |
| **T12 Resource exhaustion** | 5 | 8 | 7 | 5 | 6 | **31** |

**Risk Priority:**
1. T8 Job queue trust boundary - 34
2. T4 Sensitive data disclosure - 32
3. T1 Direct prompt injection - 31
4. T12 Resource exhaustion - 31
5. T6 Gateway identity and privilege abuse - 28
6. T2 Indirect prompt injection - 27
7. T11 Supply chain and model artifacts - 27
8. T3 Hidden-context extraction - 26
9. T10 Audit tampering - 25
10. T9 Approval workflow abuse - 24
11. T7 Tool misuse and unauthorized change - 23
12. T5 Cross-session vault decoding - 20

**Re-scored 2026-11-10 once the tuned ADR-011 gate was live.** Only T1 and T2 moved. The injection guard scores 10/10 on the corpus' injection positives with 1/32 benign false positives at `0.662`, and the joint gate blocks 28/32 model-resolved must-block rows (`scripts/tune_classifier.py`). Every detected payload routes to `local-llama`, so it cannot reach a cloud provider, trigger a state change or influence an authorization decision. That lowers T1 to 31 (damage 6→5, reproducibility 8→7, exploitability 7→6) and T2 to 27 (damage 6→5, reproducibility 7→6, exploitability 6→5). The scores stay high because the corpus is a calibration set, not held-out recall; the four documented model gaps still route public; an evading injection is still answered by the local model, with only verbatim leakage caught by the canary and quarantined; and indirect payloads depend on a caller-labelled `tool` turn. The other ten rows are unchanged: Gate 1 rejects an *unregistered* tool, while T7's residual risk is misuse of an approved tool, which RBAC and the four-eyes gate already bound.

## 7. Known gaps, in priority order

1. Close T8: authenticate queued jobs and isolate Redis.
2. Run `pytest` and `scripts/run_evals.py` in CI and fail the build below threshold. The README states that evals gate merges, and CI does not do that yet.
3. Add per-principal token and cost budgets (T12); request-rate limiting is live (ADR-013).
4. Anchor the audit-chain head outside the database (T10).
5. Add Swiss identifier recognizers and grow the golden set beyond 83 cases (T1, T4).
6. Sign and verify images (cosign), pin the three tag-only references, and add IaC and secret scanning (T11).
7. Replace development secrets with a secret-manager integration (T4, T6).

## 8. Verification

```bash
uv run pytest                                  # unit and contract tests
uv run python scripts/run_evals.py             # golden gates, writes artifacts/evals/latest.json
uv run python scripts/verify_audit_chain.py    # recompute the audit hash chain
uv run python scripts/validate_tool_catalog.py --check
uv run python scripts/update_threat_intel.py   # OSV audit of uv.lock
uv run python scripts/recalculate_dread.py --check
```

Update this document in the same commit as any change to a control, and keep the status column in section 4 in step with the code.
