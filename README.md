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

See [`HANDOVER_SPEC.md`](HANDOVER_SPEC.md) for full architectural blueprints and sequence diagrams.
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

| User | Realm roles | Purpose |
|------|-------------|---------|
| `admin` | `admin` | Break-glass superset (satisfies every requirement) |
| `alice` | `operator` | Initiator of the demo write requests |
| `bob` | `operator`, `analyst` | The second operator who decides tickets |
| `carol` | `analyst` | Read/analysis only; dashboard is forbidden |
| `dave` | `readonly` | API read-only; dashboard is forbidden |

Open **`http://localhost:8000/dashboard`** in a browser (use `localhost`, not
`127.0.0.1`, because the registered redirect URI and Keycloak's secure cookies
are scoped to that host). The gateway redirects to Keycloak, then creates a
server-side session in Redis. The browser only holds an opaque, `HttpOnly`,
`SameSite=Lax` cookie — access and refresh tokens never leave the server. The
access token is refreshed back-channel, so a 5-minute Keycloak token does not
log an operator out mid-incident.

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

Until the ARQ worker lands in Milestone 4, the seed script writes the same
suspended-ticket row and `APPROVAL_REQUESTED` audit event the worker will
produce:

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
`realm-export.json` does not update a realm that already exists. For a clean
re-import (this deletes Keycloak's state, not the audit ledger):

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
uv run mypy settings.py logging_setup.py db gateway agent
uv run python scripts/check_adrs.py
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
collector log). Health probes are excluded from tracing.

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
