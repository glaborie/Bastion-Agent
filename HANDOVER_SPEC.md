# Bastion-Agent: High-Assurance Architecture & Implementation Specification

## Project Overview
Bastion-Agent is a high-assurance, zero-trust enterprise AI agent harness and runtime written in Python (FastAPI + ARQ) and deployed via Docker Compose. It serves as a hardened policy enforcement point and control plane for enterprise agent operations in regulated environments.

---

## 1. Core Architecture & Topology

```
                              [ Client / Caller ]
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Keycloak (OIDC IdP)       │ (OAuth 2.0 / JWT issuance)
                        └─────────────┬─────────────┘
                                      │ Bearer JWT (RS256)
                                      ▼
             ┌─────────────────────────────────────────────────┐
             │       FastAPI Gateway & Command Control         │
             │  • OIDC JWT Validation & Declarative RBAC       │
             │  • Presidio Deterministic DLP Engine            │
             │  • Reversible In-Memory Token Vault (Redis)     │
             │  • ONNX Sensitivity Sequence Classifier         │
             │  • Canary Token Injection & Egress Scrubbing    │
             │  • Lightweight HTMX Command Control Center      │
             └──────────┬───────────────────┬──────────────────┘
                        │                   │
         [Async Task]   │                   │ [Sync Audit Entry]
                        ▼                   ▼
             ┌─────────────────────┐   ┌───────────────────────────────┐
             │ Redis 7             │   │ PostgreSQL 16                 │
             │ • ARQ Task Queue    │   │ • Suspended Approval States   │
             │ • AES Token Vault   │   │ • Append-Only Audit Chain     │
             └──────────┬──────────┘   └───────────────────────────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │ ARQ Agent Worker    │
             │ • Tool Execution    │
             │ • HITL Suspension   │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────────────────────────────────┐
             │ OmniRoute Gateway                               │
             │ • Cloud: OpenRouter (Cloud models)              │
             │ • Local: llama.cpp server (RTX 3060 Ti CUDA)    │
             └──────────┬───────────────────┬──────────────────┘
                        │                   │
             ┌──────────▼──────────┐   ┌────▼──────────────────────────┐
             │ OpenRouter API      │   │ llama.cpp (Qwen 2.5 7B Q4_K_M)│
             └─────────────────────┘   └───────────────────────────────┘
                                  │
                                  ▼
             ┌─────────────────────────────────────────────────┐
             │ OTel Collector Contrib Container                │
             │ • Standard OTLP Spans -> Langfuse / Arize       │
             └─────────────────────────────────────────────────┘
```

---

## 2. Directory Structure

```
Bastion-Agent/
├── docker-compose.yml
├── .env.example
├── pyproject.toml
├── README.md
├── AGENTS.md
├── config/
│   ├── keycloak/realm-export.json
│   ├── omniroute/config.yaml
│   └── otel/otel-collector-config.yaml
├── gateway/
│   ├── __init__.py
│   ├── main.py                     # FastAPI application entrypoint
│   ├── auth/                       # JWT validation, JWKS caching & RBAC dependencies
│   │   ├── __init__.py
│   │   ├── oidc.py
│   │   └── rbac.py
│   ├── dashboard/                  # Lightweight HTMX Command Control Center
│   │   ├── templates/
│   │   │   ├── base.html
│   │   │   ├── dashboard.html
│   │   │   └── partials/
│   │   │       ├── approval_table.html
│   │   │       └── eval_status.html
│   │   └── static/
│   │       └── style.css
│   └── routers/
│       ├── __init__.py
│       ├── chat.py                 # POST /v1/chat (protected API)
│       ├── approvals.py            # GET /api/approvals, POST /api/approvals/{id}/action
│       └── health.py               # GET /health, GET /api/evals/latest
├── agent/
│   ├── __init__.py
│   ├── runtime.py                  # ARQ worker & agent state machine loop
│   ├── tools/                      # Guarded tools (@tool decorator)
│   │   ├── __init__.py
│   │   ├── decorator.py
│   │   └── builtin.py              # Sample read/write tools
│   ├── dlp/                        # Two-stage DLP pipeline & token vault
│   │   ├── __init__.py
│   │   ├── presidio.py
│   │   └── vault.py                # Redis-backed AES-256 reversible token vault
│   ├── routing/                    # Sensitivity classifier & OmniRoute client
│   │   ├── __init__.py
│   │   ├── classifier.py           # ONNX sequence classifier for confidentiality
│   │   └── client.py               # OpenAI-compatible OmniRoute client
│   └── egress/                     # Canary token generator & egress filter
│       ├── __init__.py
│       └── sanitizer.py
├── db/
│   ├── __init__.py
│   ├── session.py
│   └── models.py                   # AuditLog (hash-chained) & PendingApproval models
└── tests/
    ├── __init__.py
    ├── data/
    │   └── goldens.jsonl           # Synthetic golden DLP, canary & injection test cases
    ├── test_dlp_evals.py           # DeepEval + Pytest regression test suite
    ├── test_auth_rbac.py
    └── test_egress_sanitizer.py
```

---

## 3. Detailed Component Specifications

### 3.1 Authentication & Declarative RBAC (`gateway/auth/`)
- Validate standard Bearer JWT tokens issued by Keycloak (RS256) using JWKS endpoint caching.
- Extract `realm_access.roles` and user identity (`sub`, `email`, `preferred_username`).
- Define roles: `admin`, `operator`, `analyst`, `readonly`.
- Provide FastAPI dependency `require_roles(["operator", "admin"])`.

### 3.2 Declarative Tool Guard & HITL (`agent/tools/` & `db/models.py`)
- Python `@tool` decorator:
  ```python
  @tool(
      name="execute_file_write",
      description="Writes data to storage",
      read_only=False,
      required_role="operator",
  )
  async def execute_file_write(path: str, content: str, context: AgentContext): ...
  ```
- **Allow List & Read-Only**: Tools with `read_only=True` and permitted by caller RBAC execute immediately without pausing.
- **Write Actions & Four-Eyes Principle**:
  - If `read_only=False`, execution pauses.
  - Generates a `PendingApproval` record in PostgreSQL with an HMAC-signed approval token and expiration timestamp.
  - The approving user **cannot** be the user who initiated the prompt (`initiator_id != approver_id`).
  - Returns `status: "approval_pending"` with `ticket_id` to the caller.

### 3.3 Two-Stage DLP & Reversible Token Vault (`agent/dlp/`)
- **Stage 1 (Deterministic Entity Scrubber)**: Uses `presidio-analyzer` and `presidio-anonymizer` to detect PII (PERSON, EMAIL_ADDRESS, PHONE_NUMBER, IBAN, IP_ADDRESS, API_KEYS).
- **Reversible Token Vault**:
  - Replaces detected entities with session-scoped markers: `{{ENTITY:PERSON_1}}`, `{{ENTITY:EMAIL_1}}`.
  - Maps marker -> real value in Redis under session key `vault:{session_id}`.
  - Value is encrypted with AES-256-GCM.
  - TTL is set to 30 minutes. Real PII never leaves the gateway boundary.
- **Stage 2 (Semantic Sensitivity Classifier)** (`agent/routing/classifier.py`):
  - Lightweight sequence classifier running in ONNX Runtime (CPU/DirectML) detecting internal corporate secrets/confidential IP.
  - If sensitive: sets model alias to `local-llama` (dispatched by OmniRoute to local `llama.cpp`).
  - If public/non-sensitive: sets model alias to `cloud-primary` (dispatched by OmniRoute to OpenRouter).

### 3.4 Egress Filter & Indirect Prompt Injection Defense (`agent/egress/`)
- Embed a session-unique UUID canary token (e.g., `BASTION-CANARY-<uuid4>`) inside system instructions.
- Sandboxes untrusted retrieved text and tool call outputs inside explicit `<untrusted_content>` XML fences.
- Inspects model output before delivering to client:
  - If a token with the configured `CANARY_PREFIX` is present in model output: immediately blocks response and flags security incident.
  - Reversibly restores entity placeholders (`{{ENTITY:PERSON_1}}` -> `Alice`) from Redis vault for the authorized client's response.

### 3.5 Cryptographic Audit Trail (`db/models.py`)
- Append-only PostgreSQL table `audit_logs`:
  - Fields: `id`, `timestamp`, `session_id`, `actor_id`, `event_type` (`INPUT_RECEIVED`, `DLP_REDACTION`, `ROUTING_DECISION`, `TOOL_REQUESTED`, `APPROVAL_GRANTED`, `EGRESS_FILTERED`, `RESPONSE_SENT`, `SECURITY_INCIDENT`, `ESCROW_ACCESSED`), `payload_hash` (SHA-256), `metadata_json`, `previous_hash`, `record_hash`.
  - `record_hash` computed as `SHA256(id + timestamp + actor_id + event_type + payload_hash + previous_hash)`.

### 3.6 Centralized Command Control Dashboard (`gateway/dashboard/`)
- Minimalist HTMX + Tailwind/Pico.css single-file dashboard served by FastAPI at `/dashboard`.
- Real-time polling (`hx-get="/api/approvals" hx-trigger="every 3s"`):
  - Lists pending tool approvals (Tool name, Arguments diff, Initiator, Expiration).
  - Actions: `[Approve]` and `[Reject]` (disables button if current user == initiator).
- Eval Health card displaying latest DeepEval run status (pass rate, total goldens tested, last run timestamp).

### 3.7 DeepEval Regression Test Suite (`tests/`)
- Golden dataset `tests/data/goldens.jsonl` with benchmark prompts containing PII, confidential IP, prompt injection attempts, and standard tasks.
- Pytest suite using DeepEval (`DLPRedactionMetric`, `EgressCanaryMetric`) enforcing threshold `1.0` (zero tolerance for secret leaks).
- Supports local viewing via `deepeval view` / generated report file.
