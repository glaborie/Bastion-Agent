# Bastion-Agent 🛡️

> **High-Assurance, Zero-Trust Enterprise AI Agent Harness & Control Plane**

Bastion-Agent is an enterprise-grade agent runtime designed for high-security and regulated environments. It enforces deterministic Data Leak Prevention (DLP), semantic confidential prompt routing to local inference, four-eyes human-in-the-loop tool guards, OpenTelemetry observability, and continuous regression evaluations with DeepEval.

---

## Key Capabilities

- 🔒 **Two-Stage DLP Pipeline**: Microsoft Presidio entity detection coupled with an AES-256-GCM encrypted Redis session vault for reversible anonymization.
- 🚦 **Confidentiality Routing**: Low-latency sequence classification routes confidential business prompts to a local CUDA `llama.cpp` instance (Qwen 2.5 7B on RTX 3060 Ti) via OmniRoute, and general queries to cloud providers.
- 👤 **SSO & Declarative RBAC**: Keycloak OIDC integration with role-based tool visibility and access control (`admin`, `operator`, `analyst`, `readonly`).
- 🛑 **Four-Eyes HITL Governance**: Asynchronous suspension of mutating (`read_only=False`) actions requiring secondary operator approval via an embedded HTMX Command Control Center.
- 🐤 **Egress Canary Tripwires**: Ephemeral canary tokens and XML fence isolation to detect and block prompt extraction and indirect prompt injection attacks.
- 📜 **Tamper-Evident Audit Ledger**: SHA-256 cryptographically chained audit logging in PostgreSQL for non-repudiable compliance auditing.
- 📊 **Dual Observability**: OpenTelemetry Collector exporting OTLP spans to Langfuse, Arize Phoenix, or Better Stack.
- 🧪 **Eval-Driven Gating**: DeepEval golden benchmark test suite enforcing 100% recall on secret redactions before CI merges.

---

## Architecture

See [`HANDOVER_SPEC.md`](HANDOVER_SPEC.md) for architectural blueprints and sequence diagrams.
See [`DEMO.md`](DEMO.md) for a guided, 10–15 minute end-to-end demonstration of
what is implemented today.
See [`AGENTS.md`](AGENTS.md) for OpenCode implementation directives and milestone execution.

Architectural decisions live in [`docs/adr/`](docs/adr/ADR-Index.md) (ADR-001 …
ADR-008). They describe what the system actually does; when behaviour changes,
update the ADR in the same commit. Validate the set with:

```bash
uv run python scripts/check_adrs.py
```

---

## Quick Start (Local Docker Compose)

### Prerequisites

- Docker Engine 24+ with Compose v2.24+
- NVIDIA Container Toolkit + a CUDA GPU (for the local `llama-cpp` service)
- A GGUF model in `./models/` (default: `qwen2.5-7b-instruct-q4_k_m.gguf`)

```bash
# 1. Clone & enter directory
cd /home/glaborie/projects/Bastion-Agent

# 2. Configure environment (dev-only secrets; rotate before any real deployment)
cp .env.example .env

# 3. Download the local inference model (once; ~4.7 GB, name must match exactly)
uvx --from huggingface_hub hf download \
  bartowski/Qwen2.5-7B-Instruct-GGUF \
  Qwen2.5-7B-Instruct-Q4_K_M.gguf --local-dir models
mv models/Qwen2.5-7B-Instruct-Q4_K_M.gguf models/qwen2.5-7b-instruct-q4_k_m.gguf
ls -lh models/qwen2.5-7b-instruct-q4_k_m.gguf   # must be ~4.7 GB, not 0 bytes

# 4. Start full stack
docker compose up -d

# 5. Register the routing aliases (idempotent; writes OMNIROUTE_API_KEY to .env)
uv run python scripts/omniroute_bootstrap.py --write-env
docker compose up -d --no-deps gateway worker   # only needed if a key was written

# 6. Access Command Control Center
# Gateway & Dashboard: http://localhost:8000/dashboard  (Keycloak SSO)
# Health / readiness:  http://localhost:8000/health, /health/ready
# Keycloak SSO:        http://localhost:8080
# OmniRoute:           http://localhost:8001
```

---

## Authentication & Command Control Center (Milestone 2)

Keycloak imports the `bastion` realm from `config/keycloak/realm-export.json`
on first start. It defines four roles (`admin`, `operator`, `analyst`,
`readonly`), the confidential `bastion-gateway` client used by the dashboard,
and a public `bastion-cli` client for password-grant command-line access.

### Development identities

All seeded accounts share the password **`Bastion-dev-2026!`** — a committed,
dev-only credential. Rotate or delete these users before exposing the stack.

> **Note:** `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD` in `.env` are the
> **master-realm bootstrap administrator** (`http://localhost:8080/admin`), not
> a `bastion`-realm dashboard login. The dashboard `breakglass` user below is a
> normal realm user seeded by `realm-export.json` and uses
> `Bastion-dev-2026!`. Using the bootstrap password on the dashboard login page
> returns `invalid_user_credentials`.

| User | Realm roles | Purpose |
|------|-------------|---------|
| `breakglass` | `admin` | Break-glass superset (satisfies every requirement) |
| `alice` | `operator` | Initiator of the demo write requests |
| `bob` | `operator`, `analyst` | The second operator who decides tickets |
| `carol` | `analyst` | Read/analysis only; dashboard is forbidden |
| `dave` | `readonly` | API read-only; dashboard is forbidden |

Open **`http://localhost:8000/dashboard`** in a browser (use `localhost`, not
`127.0.0.1`, because the registered redirect URI and Keycloak's secure cookies
are scoped to that host). The gateway redirects to Keycloak, then creates a
server-side session in Redis. The browser only holds an opaque, `HttpOnly`,
`SameSite=Lax` cookie — access and refresh tokens never leave the server. The
access token is refreshed back-channel, so a 15-minute Keycloak token does not
log an operator out mid-incident.

Signing out deletes the session and redirects to a **one-time same-origin
landing page** (`/auth/logged-out`) that unloads the dashboard before sending
the browser to Keycloak's end-session endpoint. A short-lived
`bastion_logged_out` cookie forces `prompt=login` on any login that races the
logout, so an in-flight dashboard poll cannot silently re-authenticate through
the still-open SSO session.

### API access with a Bearer token

The gateway accepts the same RS256 token on `/api/*` and `/auth/me`:

```bash
TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/bastion/protocol/openid-connect/token \
  -d grant_type=password -d client_id=bastion-cli \
  -d username=bob -d password='Bastion-dev-2026!' \
  -d scope='openid profile email' | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/auth/me
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/approvals
```

### Seeding a four-eyes ticket

The worker creates these tickets from real tool calls (see
[`DEMO.md`](DEMO.md) and `scripts/demo_tool_request.py`). The seed script is
still useful for populating the queue without a running worker; it writes the
same suspended-ticket row and `APPROVAL_REQUESTED` audit event:

```bash
# alice's Keycloak subject id (the initiator who must not approve)
ALICE_SUB=$(curl -s -H "Authorization: Bearer $ALICE_TOKEN" \
  http://localhost:8000/auth/me | jq -r .subject)
uv run python scripts/seed_demo_approval.py --initiator-id "$ALICE_SUB"
```

Approve it as `bob`; the dashboard disables the buttons for `alice` and the
server returns `403` if she tries anyway. Every decision appends
`APPROVAL_GRANTED` / `APPROVAL_REJECTED` to the audit chain in the same
transaction, with a hash of the free-text reason (never the text itself).

### Routes

| Method | Path | Access |
|--------|------|--------|
| GET | `/dashboard` | operator or admin |
| GET | `/dashboard/audit` | operator or admin (filter + cursor paging) |
| GET | `/dashboard/sessions/{id}` | operator or admin (audit timeline) |
| GET | `/api/approvals` | operator or admin; JSON, or HTML with `HX-Request: true` |
| POST | `/api/approvals/{id}/action` | operator or admin + CSRF (cookie auth) |
| GET | `/api/audit` | operator or admin (JSON/HTML, cursor paging) |
| POST | `/api/audit/verify` | operator or admin + CSRF; full chain verification |
| GET | `/api/sessions/{id}/timeline` | operator or admin |
| GET | `/api/evals/latest` | operator or admin |
| GET | `/auth/login`, `/auth/callback`, `/auth/logout` | public flow / session |
| GET | `/auth/me` | any authenticated identity |

### Evaluation health card

`GET /api/evals/latest` reads `EVAL_REPORT_PATH`
(default `artifacts/evals/latest.json`, mounted read-only into the gateway).
The Milestone 6 harness writes:

```json
{
  "run_id": "2026-11-09T13:00:00Z-abc123",
  "started_at": "2026-11-09T13:00:00Z",
  "finished_at": "2026-11-09T13:00:42Z",
  "total": 27,
  "passed": 27,
  "failed": 0,
  "metrics": {"DLPRedactionMetric": 1.0, "EgressCanaryMetric": 1.0},
  "git_sha": "9d1d5a9"
}
```

A missing, malformed or >24h-old report is shown as "not run yet" / stale; the
dashboard never invents a green result.

### Realm changes

Keycloak imports with the `IGNORE_EXISTING` strategy, so editing
`realm-export.json` does not update a realm that already exists. In particular,
the break-glass user is now `breakglass` (it was `admin` in an earlier
revision); an existing realm volume keeps the old username until it is renamed
in the admin console or re-imported. For a clean re-import (this deletes
Keycloak's state, not the audit ledger):

```bash
docker compose down keycloak
docker volume rm bastion-agent_keycloak_data
docker compose up -d keycloak
```

`./models` is bind-mounted read-only at `/models` inside the `llama-cpp`
container, and the filename must match `LLAMA_MODEL_FILE`. The service
crash-loops with `failed to open GGUF file ... (No such file or directory)`
until the file is present — that is the expected failure mode, not a broken
image. If you rename the file, update `LLAMA_MODEL_FILE` in `.env` to match.

The local inference plane is protected by `LLAMA_API_KEY` (passed as
`--api-key` to llama.cpp and presented by OmniRoute's `local-llama` alias).
Only change it in both places.

---

## DLP, Token Vault & Confidentiality Routing (Milestone 3)

### Modules

| Module | Responsibility |
|--------|----------------|
| `agent/dlp/vault.py` | AES-256-GCM, session-scoped reversible token vault in Redis |
| `agent/dlp/presidio.py` | Presidio analysis, custom `API_KEY` recognizers, span-level tokenisation |
| `agent/routing/classifier.py` | ONNX classifier or deterministic semantic-rule fallback |
| `agent/routing/client.py` | OpenAI-compatible OmniRoute client + `ModelRouter` alias selection |

### Token vault

Detected values are replaced with `{{ENTITY:TYPE_INDEX}}` (for example
`{{ENTITY:EMAIL_ADDRESS_1}}`). Redis stores:

- `vault:<sha256(session)>` → `token → AES-256-GCM(nonce || ciphertext)`;
- `vault:<sha256(session)>:rev` → keyed HMAC of `(type, value)` → token, so
  repeated values reuse the marker without storing plaintext;
- `vault:<sha256(session)>:seq` → per-entity counters.

AES-GCM authenticates the session id and token as AAD, so a ciphertext copied to
another session or token fails closed. The 30-minute TTL (`VAULT_TTL_SECONDS`)
is refreshed on creation and restoration; `clear(session_id)` expires it
immediately. Plaintext is never written to Redis, audit records or logs.

```python
from agent.dlp.presidio import get_dlp

dlp = get_dlp()
result = await dlp.redact("Email alice@example.com", session_id="sess-1")
restored = await dlp.restore(result.text, session_id="sess-1")
```

### Deterministic DLP

Presidio runs on the CPU with `en_core_web_sm`. The default entities are
`PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `IBAN_CODE`, `IP_ADDRESS`,
`CREDIT_CARD`, `US_SSN` and `API_KEY`; the last is a local recognizer for
provider tokens (`sk-…`, `ghp_…`, `AKIA…`, `xox…`) and `api_key = …` style
assignments. Analysis and tokenisation are fail-closed: if Presidio cannot
initialise, `DLPUnavailableError` is raised rather than passing text through.
`DLP_SCORE_THRESHOLD` (default `0.35`) is the Presidio confidence floor.

### Sensitivity classifier

With `CLASSIFIER_MODEL_PATH` unset, a deterministic weighted-marker classifier
covers explicit markings, internal-only notes, codenames, board/HR/finance
material, technical IP, customer data and sensitive personal topics. The
confidence is `weight / (weight + 2)` and `CLASSIFIER_CONFIDENCE_THRESHOLD`
(default `0.55`) decides the label; borderline prompts are `PUBLIC` by policy.

For ONNX, set `CLASSIFIER_MODEL_PATH` and (optionally)
`CLASSIFIER_TOKENIZER_PATH` (defaults to `tokenizer.json` next to the model).
The graph must take `input_ids` (plus `attention_mask` and optional
`token_type_ids`) and return two logits ordered `[PUBLIC, CONFIDENTIAL]`. A
missing model/tokenizer fails closed when the classifier is constructed rather
than silently falling back.

### Routing

`ModelRouter` maps `CONFIDENTIAL` → `MODEL_LOCAL_ALIAS` (`local-llama`) and
`PUBLIC` → `MODEL_CLOUD_ALIAS` (`cloud-primary`). Completions go to
`OMNIROUTE_BASE_URL/v1/chat/completions` with `OMNIROUTE_API_KEY`.
`CONFIDENTIAL` traffic never falls back to cloud: retries stay on the same
alias, and a local outage raises `UpstreamError` (fail closed).

```python
from agent.routing.client import ChatMessage, get_model_router

router = get_model_router()
decision = await router.aroute("Summarise this internal-only memo")
completion = await router.complete(
    [ChatMessage("user", "Summarise this internal-only memo")],
    decision=decision,
)
```

### Verification

```bash
uv run pytest -q tests/test_vault.py tests/test_dlp_presidio.py \
  tests/test_classifier.py tests/test_routing_client.py
```

The chat endpoint lands with the agent loop; the DLP, vault, classifier and
router are exercised directly by the tests and the live smoke below.

## Guarded Tools & Four-Eyes HITL (Milestone 4)

### Modules

| Module | Responsibility |
|--------|----------------|
| `agent/tools/decorator.py` | `@tool` declaration, `AgentContext`, registry, JSON argument validation |
| `agent/tools/builtin.py` | `read_system_status`, `read_file`, `execute_file_write` (workspace-confined) |
| `agent/tools/execution.py` | Request/suspend/resume state machine and audit records |
| `agent/runtime.py` | ARQ jobs plus expiry and approved-ticket cron sweeps |
| `gateway/queue.py` | Gateway → worker resume handoff with a cron fallback |

### Declaring a tool

```python
from agent.tools import AgentContext, tool


@tool(
    name="execute_file_write",
    description="Writes data to storage",
    read_only=False,
    required_role="operator",
)
async def execute_file_write(path: str, content: str, context: AgentContext) -> dict: ...
```

The decorator enforces at import time that the handler is `async`, takes
`context: AgentContext`, and annotates every JSON argument as `str`, `int`,
`float` or `bool`. Mutating tools **must** declare `required_role`; read-only
tools may omit it. Role-denied tools are filtered from
`available_tools(roles)` instead of being offered and then rejected.

### State machine

```
request ──read_only──▶ execute ──▶ EXECUTED
    └────mutating───▶ PENDING ──approve──▶ APPROVED ──resume──▶ EXECUTED
                         └────reject────▶ REJECTED
                         └────timeout───▶ EXPIRED
                                       (tool error) ──▶ FAILED
```

```python
from agent.tools.execution import request_tool_execution, resume_approved_tool

result = await request_tool_execution(
    session,
    tool_name="execute_file_write",
    arguments={"path": "reports/q3.txt", "content": "revenue"},
    context=agent_context,
)
# result.status == "approval_pending"
# result.ticket_id, result.approval_token, result.expires_at
```

The ARQ worker exposes the same operations as jobs: `execute_tool_job`,
`resume_tool_job`, `expire_stale_approvals_job` and
`resume_approved_tickets_job`. Both sweeps run every 30 s: lapsed tickets are
closed (their history stays in the ledger) and approved tickets left unexecuted
by a lost job are recovered.

### Guarantees

- **Exact-request binding**: `request_fingerprint` is a canonical SHA-256 of
  `(tool, arguments)`; the HMAC ticket covers ticket id, fingerprint and expiry
  and only its hash is stored. A changed argument at resume time marks the
  ticket `FAILED` and records `SECURITY_INCIDENT`.
- **Four eyes**: the approver must differ from the initiator, enforced in the
  service and by a database `CHECK`, and re-checked at resume. Both ids are the
  OIDC **subject** (`sub`), never a username: enqueue tool jobs with the same
  `sub` the dashboard session uses, or the comparison would span two identity
  namespaces.
- **Single execution**: the ticket row is locked `FOR UPDATE`; terminal states
  return without re-running, so a retried job cannot write twice (execution is
  at-least-once across a worker crash; tools must tolerate retries).
- **No stranded approvals**: the gateway enqueues `resume:<ticket_id>` after
  committing the decision; if Redis is down, the worker sweep executes approved
  tickets later.
- **Audit in the same transaction**: `TOOL_REQUESTED` (accepted/denied),
  `APPROVAL_REQUESTED`, `TOOL_EXECUTED` (ok/failed) and `SECURITY_INCIDENT`.
  Metadata stores argument *keys* and hashes, never values.
- **Filesystem confinement**: built-in file tools resolve paths inside
  `TOOL_WORKSPACE_ROOT`, reject absolute/traversing paths and symlink escapes,
  cap read/write sizes, and write atomically at mode `0600`.

### Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `TOOL_WORKSPACE_ROOT` | `/tmp/bastion-workspace` | Confinement root for file tools |
| `TOOL_MAX_READ_BYTES` | `262144` | Read cap |
| `TOOL_MAX_WRITE_BYTES` | `1048576` | Write cap |
| `TOOL_MAX_ARGUMENT_BYTES` | `1048576` | Reject oversized job arguments |
| `TOOL_RESUME_AUTO_ENQUEUE` | `true` | Push resume jobs; the cron sweep is the fallback |
| `ARQ_CONNECTION_TIMEOUT_SECONDS` | `2` | Gateway enqueue connect timeout |

### Verification

```bash
uv run pytest -q tests/test_tool_decorator.py tests/test_tool_execution.py
```

---

## Operator Scripts

| Script | Purpose |
|--------|---------|
| `scripts/verify_audit_chain.py` | Recompute the audit hash chain (exit `1` on tamper, `2` if it cannot run) |
| `scripts/validate_tool_catalog.py` | Registry ↔ `docs/tools/v1.json` allow-list; `--write` approves the current set |
| `scripts/validate_rbac.py` | Realm roles/users ↔ code roles ↔ tool requirements; proves four-eyes is possible |
| `scripts/recalculate_dread.py` | Recompute DREAD totals and the risk-priority list; `--check` / `--write` |
| `scripts/update_threat_intel.py` | Query OSV for every registry package in `uv.lock`; writes `artifacts/threat-intel/latest.json` |
| `scripts/demo_tool_request.py` | Originate a guarded tool call for the demo (see `DEMO.md`) |
| `scripts/seed_demo_approval.py` | Seed a suspended ticket without a worker |
| `scripts/omniroute_bootstrap.py` | Register OmniRoute provider aliases and the gateway key |
| `scripts/check_adrs.py` | Validate the ADR set and index |

The validators are deterministic and offline; run them in CI before deployment.
`verify_audit_chain.py` needs a reachable database and is therefore a
post-deploy check rather than a unit test.

The dependency audit needs network access to `api.osv.dev` and exits `1` on any
unignored finding, so it belongs in a scheduled or post-deploy job rather than
the offline test gate. Accepted risks are named explicitly:

```bash
uv run python scripts/update_threat_intel.py --ignore GHSA-xxxx-yyyy-zzzz
uv run python scripts/update_threat_intel.py --offline artifacts/threat-intel/latest.json
```

The `--offline` form re-evaluates the last saved report, which lets CI gate
without network access. The report records the `uv.lock` SHA-256, the OSV batch
URL, severity, CVSS vectors and fixed versions for each finding.

## Local Development (without Docker)

```bash
uv sync                      # installs the project + dev group (3.11)
docker compose up -d db redis   # only the dependencies you need

uv run uvicorn gateway.main:app --reload
uv run arq agent.runtime.WorkerSettings
```

### Verification

```bash
uv run ruff check .          # lint
uv run mypy settings.py logging_setup.py db gateway agent scripts
uv run pylint settings.py logging_setup.py telemetry.py db gateway agent tests scripts
uv run python scripts/check_adrs.py
uv run python scripts/validate_tool_catalog.py --check
uv run python scripts/validate_rbac.py
uv run python scripts/recalculate_dread.py --check
uv run pytest -m "not integration"   # unit tests (no database required)
```

Database-backed tests need a disposable PostgreSQL 16 instance. The suite
refuses to run against a database whose name does not contain `test`:

```bash
docker run --rm -d --name bastion-test-db -p 55433:5432 \
  -e POSTGRES_USER=bastion -e POSTGRES_PASSWORD=bastion \
  -e POSTGRES_DB=bastion_test postgres:16-alpine

TEST_DATABASE_URL=postgresql+asyncpg://bastion:bastion@localhost:55433/bastion_test \
  uv run pytest -m integration
```

---

## Routing bootstrap (OmniRoute)

`scripts/omniroute_bootstrap.py` reconciles the routing contract in
`config/omniroute/config.yaml`: the llama.cpp provider node, the llama.cpp and
OpenRouter connections, the `local-llama` / `cloud-primary` combos, and the
gateway's `/v1` API key. It is idempotent and ends with a smoke test of both
aliases:

```bash
uv run python scripts/omniroute_bootstrap.py --write-env
```

Re-run it after `docker compose down -v` (which wipes OmniRoute's volume), after
rotating `LLAMA_API_KEY` or `OPENROUTER_API_KEY`, or when adding models to a
combo. It requires `OPENROUTER_API_KEY` in `.env`.

---

## Observability (Langfuse Cloud + Arize AX)

The gateway and worker export OTLP/HTTP spans to `otel-collector`, which fans
them out to Langfuse Cloud and Arize AX (and mirrors batch counters to the
collector log). Health probes and the dashboard's polling endpoints
(`/api/approvals` every 3 s, `/api/evals/latest` every 30 s) are excluded from
tracing, so an open dashboard does not burn a backend quota; the four-eyes
decision endpoint stays traced.

Remote export is **currently paused** — the collector's `traces` pipeline
exports to `debug` only. Re-add `otlphttp/langfuse` and/or `otlphttp/arize` to
the pipeline's `exporters` list in `config/otel/otel-collector-config.yaml` to
resume fan-out.

Configure in `.env`:

```dotenv
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_OTLP_ENDPOINT=https://cloud.langfuse.com/api/public/otel  # EU; us./jp./hipaa. for other regions
LANGFUSE_OTLP_AUTH=<base64 of "public_key:secret_key">

ARIZE_OTLP_ENDPOINT=https://otlp.arize.com/v1
ARIZE_SPACE_ID=<space id>
ARIZE_API_KEY=<arize api key>
ARIZE_PROJECT_NAME=bastion-agent        # x-project-name routing header
```

Build the Langfuse Basic credential (must be regenerated whenever a key is
rotated — a stale value makes the collector log `401 Unauthorized`):

```bash
python -c "import base64;print(base64.b64encode(b'pk-lf-...:sk-lf-...').decode())"
```

Verify end to end: make a request (`curl -s http://localhost:8000/docs >/dev/null`),
then confirm the collector shows no `Exporting failed` lines and the trace
appears in Langfuse under `service.name=bastion-gateway`.

---

## Troubleshooting

### `llama-cpp` restarts with `failed to open GGUF file ... (No such file or directory)`

`./models` is bind-mounted at `/models`, and the file named by `LLAMA_MODEL_FILE`
must exist there. Verify with `ls -lh models/`. A 0-byte file means an
interrupted download — re-run the `hf download` step. The service crash-loops
until the model is present; that is expected.

With 8 GB of VRAM, Q4_K_M at `LLAMA_CTX_SIZE=8192` uses ~6.6 GB once the desktop
is accounted for. If you see CUDA out-of-memory errors, lower
`LLAMA_CTX_SIZE` (e.g. 4096) or `LLAMA_N_GPU_LAYERS`.

### Container hardening notes

- **Host exposure** — every published port is bound to `127.0.0.1`, including
  the gateway and Keycloak. To serve the dashboard or IdP beyond this host, put
  a TLS reverse proxy in front and set `FORWARDED_ALLOW_IPS` to that proxy's
  address (never `*`).
- **Capabilities** — all services run with `no-new-privileges` and
  `cap_drop: [ALL]`. `db` and `redis` add back only the capabilities their
  entrypoints need to drop privileges (`CHOWN`, `SETUID`, `SETGID`, …). Redis
  also keeps `DAC_OVERRIDE` so its entrypoint can inspect a `redis`-owned
  `/data` before dropping privileges; `redis-server` itself runs as the
  unprivileged `redis` user.
- **Image pinning** — third-party images are pinned by tag **and** digest.
  Refresh with `docker buildx imagetools inspect <image>` and update the digest.
  The locally built `rigging/omniroute` image keeps its tag (no registry digest).
- **No `container_name` on gateway/worker** — they are replica-safe; Compose
  derives names such as `bastion-agent-worker-1`.
- **No healthcheck on `otel-collector`** — the image is distroless (no shell).
  It exposes the `health_check` extension on `:13133` for external probes;
  tracing consumers use `service_started` because tracing is best-effort.
- **GPU** — `llama-cpp` requests an NVIDIA device through
  `deploy.resources.reservations.devices`, which needs the NVIDIA Container
  Toolkit and a Compose runtime that supports device reservations. On a
  CPU-only host use the `server` image, set `LLAMA_N_GPU_LAYERS=0`, and remove
  that reservation block.

### Sign out returns `{"detail":"cross-origin request rejected"}`

CSRF-protected mutations compare the browser's `Origin`/`Referer` with the
request `Host`. Loopback aliases (`localhost`, `127.0.0.1`, `::1`) are treated
as equivalent because Windows/WSL and Docker Desktop port forwarding can
rewrite the host between the browser and the gateway. `Origin: null` is
accepted only after the per-session CSRF token has matched: embedded or
sandboxed browser views send it, and a cross-origin attacker cannot read the
token. If you front the gateway with a reverse proxy under a different
hostname, browse to that same hostname and set `FORWARDED_ALLOW_IPS` to the
proxy address so `X-Forwarded-Host` is trusted.

### Keycloak reports `invalid_user_credentials` or "user not found" for `admin`

There are two different identities:

- `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD` (`.env`) is the **master-realm**
  bootstrap administrator used at `http://localhost:8080/admin`.
- The dashboard break-glass user is **`breakglass`** in the **`bastion`-realm**,
  seeded from `config/keycloak/realm-export.json`, with password
  `Bastion-dev-2026!`.

`admin` is not a `bastion`-realm user, so using that name on the dashboard
login page fails (or falls back to the bootstrap password and logs
`invalid_user_credentials`). Verify the realm credential directly:

```bash
curl -s -X POST http://localhost:8080/realms/bastion/protocol/openid-connect/token \
  -d grant_type=password -d client_id=bastion-cli \
  -d username=breakglass -d password='Bastion-dev-2026!'
```

### `redis` is unhealthy with `MISCONF Redis is configured to save RDB snapshots` or `Permission denied`

A `/data` directory that was previously written by a root-owned `redis-server`
can leave files that the unprivileged `redis` user cannot replace. The compose
command now passes `redis-server` directly so the image entrypoint chowns
`/data` and drops privileges; for a volume created by an older revision, repair
the ownership once:

```bash
docker exec -u 0 bastion-redis chown -R redis:redis /data
docker compose restart redis
```

### `ports are not available: /forwards/expose returned unexpected status: 500` (WSL2 + Docker Desktop)

Docker Desktop publishes host ports on the Windows side, so any port inside a
Hyper-V excluded range cannot be bound — even though WSL itself can bind it.
Redis's 6379 commonly lands in one of those ranges. Check:

```powershell
powershell.exe -NoProfile -Command "netsh int ipv4 show excludedportrange protocol=tcp"
```

Then pick a host port outside the listed ranges and update both values in `.env`:

```dotenv
REDIS_PORT=26379
REDIS_URL=redis://:<password>@localhost:26379/0
```

Alternatively reclaim the range from an elevated Windows prompt with
`net stop winnat && net start winnat` (restart Docker Desktop afterwards).

---

## Running DeepEval Regression Tests

```bash
uv run pytest tests/test_dlp_evals.py -v
# Open local eval results viewer:
uv run deepeval view
```
