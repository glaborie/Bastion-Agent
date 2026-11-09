# AGENTS.md — Implementation Instructions for OpenCode (DeepSeek V4)

## Role & Mission
You are the Lead Systems Architect and Core Implementation Agent for **Bastion-Agent**.
Your task is to build out the entire repository from scratch according to `HANDOVER_SPEC.md`.

## Technology Stack & Constraints
- **Python**: 3.11+ using `uv` for package management (`pyproject.toml`).
- **Frameworks**: FastAPI, ARQ (asyncio Redis worker), SQLAlchemy 2.0 (asyncpg), Pydantic v2.
- **Security & DLP**: Microsoft Presidio (`presidio-analyzer`, `presidio-anonymizer`), `cryptography` (AES-256-GCM), `onnxruntime` for distilled local classification.
- **Inference & Routing**: OmniRoute client (OpenAI-compatible) routing to local `llama.cpp` container (RTX 3060 Ti CUDA) or OpenRouter API.
- **Observability**: OpenTelemetry Python SDK exporting to `otel-collector-contrib` (dispatches to Langfuse/Arize).
- **Evaluation**: DeepEval (`deepeval`) + Pytest for deterministic golden dataset gating (zero-tolerance threshold).
- **Containerization**: `docker-compose.yml` defining `gateway`, `worker`, `db` (Postgres 16), `redis` (Redis 7), `keycloak`, `omniroute`, `llama-cpp`, and `otel-collector`.

## Milestones & Execution Plan

### Milestone 1: Project Scaffold, Compose & DB Models
1. Initialize `pyproject.toml` with `uv` dependencies.
2. Create `docker-compose.yml` and `.env.example` defining all 8 services and volumes.
3. Write `db/models.py` with `AuditLog` (SHA-256 hash chaining) and `PendingApproval`.
4. Create async database connection manager in `db/session.py`.

### Milestone 2: Auth, RBAC & Command Control Dashboard
1. Implement `gateway/auth/oidc.py` (JWKS caching, JWT RS256 validation) and `gateway/auth/rbac.py` (`require_roles`).
2. Provide a pre-seeded Keycloak realm configuration (`config/keycloak/realm-export.json`).
3. Build the HTMX Command Control dashboard in `gateway/dashboard/` with `/dashboard`, polling `/api/approvals`, and four-eyes enforcement UI.

### Milestone 3: Two-Stage DLP & Reversible Token Vault
1. Implement `agent/dlp/vault.py` managing AES-256-GCM encrypted Redis mappings (`{{ENTITY:TYPE_INDEX}}` <-> plaintext) with 30-min TTL.
2. Implement `agent/dlp/presidio.py` wrapping Presidio Analyzer & Anonymizer with reversible replacement.
3. Implement `agent/routing/classifier.py` using ONNX Runtime (or semantic rule classifier fallback) to tag prompts as `CONFIDENTIAL` vs `PUBLIC`.
4. Implement `agent/routing/client.py` routing requests to OmniRoute with appropriate model alias (`local-llama` vs `cloud-primary`).

### Milestone 4: Tool Guard, Four-Eyes HITL & ARQ Worker
1. Implement `agent/tools/decorator.py` defining `@tool(name, read_only, required_role)`.
2. Implement built-in tools in `agent/tools/builtin.py` (e.g. read_system_status, execute_file_write).
3. Implement `agent/runtime.py` ARQ worker:
   - Evaluates caller role against tool requirement.
   - If `read_only=False`: suspends execution, inserts `PendingApproval`, returns ticket.
   - On approval callback: verifies `approver_id != initiator_id`, resumes execution.

### Milestone 5: Egress Sanitizer, Canary Tripwires & Audit Logger
1. Implement `agent/egress/sanitizer.py`:
   - Injects session-unique `CANARY-<uuid>` into system prompts.
   - Wraps external/tool outputs in `<untrusted_content>` isolation boundaries.
   - Scans output for canary string; trips circuit breaker if leaked.
   - Restores reversible entity tokens for authorized recipient.
2. Wire synchronous audit logging into every step of the request lifecycle.

### Milestone 6: Golden Dataset & DeepEval Test Harness
1. Populate `tests/data/goldens.jsonl` with 25+ synthetic benchmark test cases (PII variants, corporate confidential prompts, prompt extraction/canaries, jailbreak probes).
2. Implement `tests/test_dlp_evals.py` using DeepEval metrics (`DLPRedactionMetric`, `EgressCanaryMetric`) asserting score == 1.0.
3. Ensure `pytest` passes cleanly.

## Quality Standards
- Strict type hints (`mypy` compatible).
- Clean logging with structured context.
- Zero mock shortcuts in core security validation—every guardrail must be active and tested.
