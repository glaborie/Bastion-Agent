# THREAT_MODEL.md

Bastion-Agent threat model

- Version: 2.0
- Last updated: 2026-11-10
- Reviewed against: commit `f7cb5f2`
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

- One deployment serves one organisation. There are no per-tenant keys or per-tenant isolation.
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
  -> route: local llama.cpp (confidential or injected) | cloud (public)        [boundary 3]
  -> system prompt gets session canary; role=tool turns are fenced
  -> model via OmniRoute
  -> egress inspection (canary scan, quarantine) -> token restore              [boundary 4]
  -> audit EGRESS_FILTERED, SECURITY_INCIDENT on block
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
| Tool catalog allow-list (`docs/tools/v1.json`) | PARTIAL | build-time check only, no runtime filtering |
| Dependency audit against OSV | PARTIAL | script exists, not run in CI |
| Test and eval gate in CI | PLANNED | CI runs pylint with `--exit-zero` only |
| Kill-switch tiers | PLANNED | ADR-009 only |
| Per-principal rate limits and token budgets | PLANNED | none found |
| Signed or re-derived identity on queued jobs | PLANNED | see T8 |
| External anchoring of the audit chain | PLANNED | see T10 |
| Langfuse and Phoenix exporters | PLANNED | collector ships with the `debug` exporter |

## 5. Threats

### T1. Direct prompt injection and jailbreak

- References: `LLM01:2026`, `ASI01`, `AML.T0051.000`, `AML.T0054`
- Attack: a user crafts input that overrides instructions or extracts data.
- Controls:
  - LIVE: injection guard evaluated first in the classifier ensemble (ADR-011). A positive result labels the prompt CONFIDENTIAL, so it never reaches a cloud provider.
  - LIVE: the classifier fails closed. A missing graph, session error, malformed output or digest mismatch resolves to CONFIDENTIAL.
  - LIVE: the canary tripwire catches a successful instruction override that leaks the marker (T3).
  - LIVE: no authorization decision depends on model output.
- Residual risk:
  - The injected prompt is still answered by the local model. The response passes egress inspection, but nothing else evaluates it for harmful content.
  - The deterministic fallback classifier (`ENVIRONMENT=local` only) cannot detect injection. Non-local deployments without the ONNX models refuse to start.
  - The golden set has 10 injection cases. That is a regression check, not a recall estimate.
- Verification: `tests/test_classifier.py`, `tests/test_classifier_evals.py`, `tests/data/goldens.jsonl`.

### T2. Indirect prompt injection through tool or retrieved content

- References: `LLM01:2026`, `ASI01`, `AML.T0051.001`
- Attack: instructions hidden in tool output or retrieved documents.
- Controls:
  - LIVE: content in `role: tool` turns is wrapped in `<untrusted_content source="...">`. Embedded fence tags are neutralised so a payload cannot close the fence. The `source` attribute is sanitised.
  - LIVE: the classifier scans all turns, including tool turns, on the raw text.
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
  - LIVE: one `CANARY-<uuid4>` per vault session. It is random, not derived from the session id.
  - LIVE: the output scan matches any token with the configured prefix, not only the current session's value. A hit discards the response, writes a `SECURITY_INCIDENT` and quarantines the session (default 900 s). The quarantine check runs before the next inference call.
  - LIVE: if Redis is unreachable the gateway returns 503. It never delivers an unscanned response.
- Residual risk: the canary detects verbatim leakage only. Paraphrased or partial extraction is not detected. The system prompt contains no secrets by design, which limits the impact.
- Verification: `tests/test_egress_sanitizer.py`, `tests/test_chat.py`.

### T4. Sensitive data disclosure to a cloud model or in responses

- References: `LLM02:2026`, `AML.T0057`
- Attack: PII or secrets in prompts reach an external provider, or are echoed in output.
- Controls:
  - LIVE: Presidio replaces entities with `{{ENTITY:TYPE_N}}` markers before inference. Default entity list: PERSON, EMAIL_ADDRESS, PHONE_NUMBER, IBAN_CODE, IP_ADDRESS, CREDIT_CARD, US_SSN, and a custom API_KEY recognizer (provider token formats and secret assignments).
  - LIVE: the vault stores values as AES-256-GCM ciphertext in Redis. The AAD binds each ciphertext to its session and token. A 30-minute TTL applies.
  - LIVE: routing classifies the raw text, so redaction cannot weaken the verdict. Confidential prompts go to the local model.
  - LIVE: the audit ledger stores a hash of the request, never prompt text or tool argument values.
  - LIVE: any DLP failure returns 503. Unredacted text is never forwarded.
- Residual risk:
  - Presidio detects patterns and named entities. It does not detect confidential business content without identifiers. That is the classifier's job, and it is probabilistic.
  - The default entity list has no Swiss-specific identifiers (for example the AHV/AVS number). Add custom recognizers before a Swiss deployment.
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
- Residual risk: a single key protects all sessions. There are no per-tenant keys.
- Verification: `tests/test_vault.py`, `tests/test_chat_contract.py`.

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
  - PARTIAL: Gate 1 catalog. An unregistered tool name is rejected at runtime. The versioned `docs/tools/v1.json` is compared with the registry only by `scripts/validate_tool_catalog.py --check`. Runtime filtering of the model-facing tool list is not wired.
  - PLANNED: kill-switch tiers and autonomy budgets (ADR-009).
- Residual risk: when an agent loop is added, the model becomes a source of tool requests. The loop must carry the end user's identity into `AgentContext`, not a service identity, and Gate 1 must be enforced at runtime before that change ships.
- Verification: `tests/test_tool_decorator.py`, `tests/test_tool_execution.py`, `tests/test_rbac.py`, `scripts/validate_tool_catalog.py --check`.

### T8. The job queue as an unauthenticated trust boundary

- References: `ASI03`, `LLM03:2026`
- Attack: a party with write access to the ARQ Redis queue enqueues `execute_tool_job` with a chosen `actor_id` and `roles`.
- Finding: `execute_tool_job` builds the `AgentContext` from job arguments. The worker does not re-verify the identity or the roles. Anyone who can enqueue can assert any principal. Because the approval check compares initiator and approver subjects, a forged initiator identity also weakens the four-eyes rule.
- Controls:
  - PLANNED: sign job payloads with a key the enqueuer alone holds, or enqueue only an opaque reference and resolve identity and roles from a server-side record.
  - PLANNED: separate Redis ACL users for gateway and worker, TLS, and no host port exposure. The development compose file publishes Redis on a host port for the demo.
- Residual risk: until this is closed, treat Redis write access as equivalent to administrator access.

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
  - LIVE: payloads are stored as hashes. Argument values and prompt text never enter the ledger.
- Residual risk:
  - A chain inside the same database detects partial edits. An attacker with write access can recompute the whole chain. Detecting that needs the head hash exported to a separate system or write-once store, plus an INSERT-only database role. Neither is implemented.
- Verification: `tests/test_audit_chain.py`.

### T11. Supply chain and model-artifact tampering

- References: `LLM04:2026`, `LLM05:2026`, `ASI04`, `AML.T0010`
- Attack: a vulnerable dependency, a swapped classifier model, a poisoned container image.
- Controls:
  - LIVE: classifier ONNX graphs are digest-checked. A mismatch fails closed to CONFIDENTIAL.
  - PARTIAL: `scripts/update_threat_intel.py` queries every package in `uv.lock` against OSV and exits non-zero on unignored findings. It is not run in CI.
  - PLANNED: SBOM generation, image pinning and signing, pinned GitHub Actions throughout, a CI gate on the OSV script.
- Residual risk: the LLM served through OmniRoute and llama.cpp is not integrity-checked by this project.

### T12. Resource exhaustion and denial of service

- References: `LLM06:2026` (Unbounded Consumption), `AML.T0029`
- Attack: oversized or repeated requests, runaway token spend.
- Controls:
  - LIVE: at most 64 messages, 32,768 characters per message, 65,536 in total, `max_tokens` at most 8192. A tool argument size cap applies.
  - LIVE: a quarantined session cannot continue to consume inference.
  - PLANNED: per-principal rate limits and token or cost budgets. None are implemented.
- Residual risk: fail-closed design is a deliberate trade. An outage of Presidio, Redis or the classifier denies service instead of degrading security.

## 6. Known gaps, in priority order

1. Close T8: authenticate queued jobs and isolate Redis.
2. Run `pytest` and `scripts/run_evals.py` in CI and fail the build below threshold. The README states that evals gate merges, and CI does not do that yet.
3. Wire runtime enforcement of the tool catalog (T7) before adding any agent loop.
4. Add per-principal rate limits and budgets (T12).
5. Anchor the audit-chain head outside the database (T10).
6. Add Swiss identifier recognizers and grow the golden set beyond 75 cases (T1, T4).
7. Wire the OSV script into CI and add an SBOM (T11).
8. Replace development secrets with a secret-manager integration (T4, T6).

## 7. Verification

```bash
uv run pytest                                  # unit and contract tests
uv run python scripts/run_evals.py             # golden gates, writes artifacts/evals/latest.json
uv run python scripts/verify_audit_chain.py    # recompute the audit hash chain
uv run python scripts/validate_tool_catalog.py --check
uv run python scripts/update_threat_intel.py   # OSV audit of uv.lock
```

Update this document in the same commit as any change to a control, and keep the status column in section 4 in step with the code.