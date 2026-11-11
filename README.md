# Bastion-Agent 🛡️

> **High-Assurance, Zero-Trust Enterprise AI Agent Harness & Control Plane**

Bastion-Agent is an enterprise-grade agent runtime designed for high-security and regulated environments. It enforces deterministic Data Leak Prevention (DLP), semantic confidential prompt routing to local inference, four-eyes human-in-the-loop tool guards, OpenTelemetry observability, and continuous regression evaluations with DeepEval.

---

## Key Capabilities

- 🔒 **Two-Stage DLP Pipeline**: Microsoft Presidio entity detection coupled with an AES-256-GCM encrypted Redis session vault for reversible anonymization.
- 🚦 **Confidentiality Routing**: Low-latency sequence classification routes confidential business prompts to a local CUDA `llama.cpp` instance (Qwen 2.5 7B on RTX 3060 Ti) via OmniRoute, and general queries to cloud providers.
- 👤 **SSO & Declarative RBAC**: Keycloak OIDC integration with role-based tool visibility and access control (`admin`, `operator`, `analyst`, `readonly`).
- 🛑 **Four-Eyes HITL Governance**: Asynchronous suspension of mutating (`read_only=False`) actions requiring secondary operator approval via an embedded HTMX Command Control Center.
- 🐤 **Egress Canary Tripwires**: Ephemeral canary tokens and XML fence isolation block any answer that repeats the marker — the deterministic proof of verbatim prompt extraction; an answer that merely *claims* to disclose its instructions is flagged, not blocked.
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
git clone https://github.com/glaborie/Bastion-Agent.git
cd Bastion-Agent

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

### Upgrading the pinned images

Every image the stack ships is scanned by `scripts/scan_images.sh` (see ADR-016).
Two notes for the current pins:

- **Keycloak 26.8.2** cannot open the H2 dev-file written by 26.0: it crash-loops
  with `Wrong user name or password [28000-240]`. Reset the dev volume once; the
  realm is re-imported from `config/keycloak/realm-export.json`.
  `docker compose stop keycloak && docker compose rm -f keycloak && docker volume rm bastion-agent_keycloak_data && docker compose up -d keycloak`
- **OTel collector 0.165.0** accepts the existing configuration, including all
  three overlays. Validate before rolling:
  `docker run --rm -v "$PWD/config/otel:/etc/otel:ro" --entrypoint /otelcol-contrib otel/opentelemetry-collector-contrib:0.165.0 validate --config=/etc/otel/otel-collector-config.yaml --config=/etc/otel/otel-collector-no-export.yaml`

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
| GET | `/dashboard/demo` | operator or admin (demo console: allow-listed scenarios) |
| GET | `/dashboard/chat` | operator or admin (guarded chat UI, CSRF on send) |
| GET | `/dashboard/audit` | operator or admin (filter + cursor paging) |
| GET | `/dashboard/sessions/{id}` | operator or admin (audit timeline) |
| POST | `/dashboard/demo/runs` | operator or admin + CSRF; form field `scenario_id` only |
| GET | `/api/dashboard/demo/runs/{id}` | operator or admin (HTML run panel, polled) |
| GET | `/api/approvals` | operator or admin; JSON, or HTML with `HX-Request: true` |
| GET | `/api/incidents` | operator or admin (HTML panel: 10 most recent `SECURITY_INCIDENT` rows) |
| POST | `/api/approvals/{id}/action` | operator or admin + CSRF (cookie auth) |
| GET | `/api/audit` | operator or admin (JSON/HTML, cursor paging) |
| POST | `/api/audit/verify` | operator or admin + CSRF; full chain verification |
| GET | `/api/sessions/{id}/timeline` | operator or admin |
| GET | `/api/evals/latest` | operator or admin |
| GET | `/auth/login`, `/auth/callback`, `/auth/logout` | public flow / session |
| GET | `/auth/me` | any authenticated identity |

### Rate limiting

Request rate is bounded per principal by a Redis token bucket (ADR-013), so the
budget is shared by every gateway replica instead of multiplying with the
process count. The bucket is keyed on the JWT `sub`; signing in again does not
reset it.

| Scope | Routes | Default budget |
|-------|--------|----------------|
| `dashboard` | pages, HTMX partials, `/api/approvals`, `/api/audit`, `/api/evals/latest`, `/api/incidents`, `/api/dashboard/demo/runs/*` | 60 requests / 60 s |
| `chat` | `POST /v1/chat` | 120 requests / 60 s |

Tune it with `RATE_LIMIT_ENABLED`, `RATE_LIMIT_WINDOW_SECONDS`,
`RATE_LIMIT_DASHBOARD_PER_WINDOW` and `RATE_LIMIT_CHAT_PER_WINDOW` (see
`.env.example`). Health probes, the OIDC login flow and static assets are
exempt; Keycloak's brute-force protection owns failed-login throttling.

A refusal is `429` with `Retry-After` and `RateLimit-Limit` /
`RateLimit-Remaining` / `RateLimit-Reset`. JSON callers get the detail, while
dashboard pages and HTMX fragments render the normal error page with the same
header. A limiter outage is `503`, not an unlimited route: Redis already gates
the vault and canary path, so degrading only this control would be the wrong
failure direction.

```bash
# Prove the bucket against the local Redis (CI runs this as a gate).
REDIS_TEST_URL=redis://localhost:56379/0 uv run pytest -m redis_integration \
  tests/test_rate_limit_redis.py
```

### Security incidents panel

The dashboard polls `GET /api/incidents` every 15 seconds and renders the ten
most recent `SECURITY_INCIDENT` records: stage, reason, actor, route and a link
to the session timeline. Only machine metadata from the hash-chained ledger is
shown, never prompt text. The full filterable history stays at
`/dashboard/audit?event_type=SECURITY_INCIDENT`.

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
| `agent/routing/classifier.py` | ADR-011 injection+safety ensemble, single-graph ONNX, or local-only rule fallback |
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
`CREDIT_CARD`, `US_SSN`, `API_KEY`, `ADDRESS`, `DATE_OF_BIRTH` and
`AHV_NUMBER`. The last four are local shape recognizers: provider tokens
(`sk-…`, `ghp_…`, `AKIA…`, `xox…`) and `api_key = …` assignments; a street with
a house number followed by a postal code and a place (`Bahnhofstrasse 12, 8001
Zürich`); a date introduced by an explicit birth anchor (`Born April 7, 1996`,
`Né le 7 avril 1996`); and a Swiss AHV/AVS number
(`756.1234.5678.97`), accepted in dotted, space-grouped or bare form only when
its EAN-13 check digit holds. Presidio's generic `LOCATION` and `DATE_TIME` are deliberately not
enabled: over the golden corpus they label `UDP`, a GitHub token and `the board
minutes` as PII. Analysis and tokenisation are fail-closed: if Presidio cannot
initialise, `DLPUnavailableError` is raised rather than passing text through.
`DLP_SCORE_THRESHOLD` (default `0.35`) is the Presidio confidence floor.

Text is language-detected first (seeded, offline `langdetect`). A confident
non-English verdict skips the NER entities and keeps the pattern recognizers, so
a French or German prompt is no longer rewritten as a person name;
`DLP_LANGUAGE_MIN_CONFIDENCE` (default `0.80`) is the floor below which the text
is analyzed as English, preserving NER coverage for short English prompts.

**A DLP hit keeps the turn local.** `ModelRouter` maps `CONFIDENTIAL` to
`local-llama` and `PUBLIC` to `cloud-primary`, but when the DLP stage redacted at
least one entity the request goes to `local-llama` even though the label stays
`PUBLIC`. `RouteDecision.override` and the `ROUTING_DECISION` audit row record
`pii_detected`, so the label and the route are both legible. The rule is a proxy
for incomplete recall: if the stage found personal data in the prompt, it is not
trusted with the rest of it. A local-model failure on such a prompt returns
`503` with a `SECURITY_INCIDENT` — never a cloud fallback.

### Sensitivity classifier

The production gate is the ADR-011 two-model ensemble. Set
`CLASSIFIER_INJECTION_MODEL_PATH` and `CLASSIFIER_SAFETY_MODEL_PATH` (and their
tokenizers) to render text as `CONFIDENTIAL` or `PUBLIC`:

| Guard | Model | What it answers |
|-------|-------|-----------------|
| Injection | `Horizon-Labs/prompt-injection-guard-small` | Is this text manipulating the model? |
| Safety | `onnx-community/content-safety-guard-small-ONNX` | Is this content unsafe, and in which category? |

The injection guard is evaluated first and cannot be overridden
(`CLASSIFIER_INJECTION_PROFILE=production` → `0.662`; `recall-first` → `0.5`).
Then the safety guard's aggregate `unsafe >= 0.5` routes `unsafe_content`, and
`privacy`, `fraud_manipulation`, `criminal_planning` or
`unauthorized_advice >= 0.3` route their own reason code. Everything else is
`public_content`. Long documents are scanned as overlapping windows and the
maximum score wins. Both guards fail closed: any inference error or malformed
output yields `CONFIDENTIAL`.

The deterministic rule classifier stays active as a **floor** in the ensemble:
explicit markings, board/HR/finance material, technical IP and customer data
are `CONFIDENTIAL` even though a content-safety model scores them as harmless.
The floor is evaluated after the model verdict and can only add `CONFIDENTIAL`
decisions; `CLASSIFIER_RULES_FLOOR=false` disables it for evaluation runs.
Two floor families are deliberate: `diagnos*` covers medical-condition text
(Presidio has no entity for it) and IBAN shapes are `financial_identifier`
(a trailing period once moved the privacy score from 0.582 to 0.201).

The gate is tuned against the ADR-006 corpus, and the sweep is reproducible:

```bash
uv run pytest -q tests/test_classifier_evals.py tests/test_dlp_evals.py
uv run python scripts/tune_classifier.py
```

The 2026-11-10 sweep retained `0.662 / 0.5 / 0.3`: lowering injection to the
model card's `0.5` routes the security-training translation (0.614) to the local
model, `unsafe = 0.3` admits the prompt-injection explainer (0.364), and
`category = 0.2` gains nothing once the `diagnos*` floor blocks the one case it
would have caught. ADR-011 records the measured gaps and the caveat that the
corpus is a calibration set, not held-out evidence.

Latency is measured, not assumed: `scripts/measure_classifier_latency.py`
reports percentiles per prompt on the configured provider and samples GPU
memory, and `scripts/benchmark_classifier_goldens.py` times `classify()` over
the whole golden corpus. On the 2026-11-10 run the int8 ensemble costs 22–40 ms
p50 (p95 ≤ 51 ms) on the CPU for prompt-sized input and ~1.6 s for a
1,000-token memo that is windowed. The int8 graphs are *slower* on CUDA, because
`MatMulInteger` and `DynamicQuantizeLinear` fall back to the CPU and the copies
cost more than the matmuls they surround; the pinned repositories also ship
fp32 graphs with real CUDA kernels, and those report p95 40.5 ms over the
corpus on an RTX 3060 Ti (2026-11-11). `CLASSIFIER_EXECUTION_PROVIDER`
therefore defaults to `cpu`; a GPU deployment builds the `runtime-gpu` image
variant and uses `docker-compose.gpu.yml`, which sets `auto` and the fp32
graphs (`CLASSIFIER_*_MODEL_GPU_PATH`) with the separately calibrated
`CLASSIFIER_SAFETY_UNSAFE_THRESHOLD_GPU=0.6`. `cuda` needs `onnxruntime-gpu`
and fails closed without it; the fp32 sessions reserve ~1.27 GiB, so only the
gateway opens them (ADR-011 records the numbers).

Demo the whole thing with:

```bash
uv run python scripts/demo_classifier.py
uv run python scripts/demo_classifier.py --no-rules-floor "strictly confidential"
```

The models are mounted at `/app/models:ro` on `gateway` and `worker`; download
them with the commands in `.env.example`. Their SHA-256 digests are pinned there
and verified before a session opens.

With both paths unset, a deterministic weighted-marker classifier covers
explicit markings, internal-only notes, codenames, board/HR/finance material,
commercial substance (forecasts, margin analysis), contract language (indemnity,
liability, governing law), technical IP, customer data and sensitive personal
topics. The confidence is `weight / (weight + 2)` and
`CLASSIFIER_CONFIDENCE_THRESHOLD` (default `0.55`) decides the label; every
domain marker weighs 3.0, so one marker routes to the local model, and only a
lone codename (weight 2.0) stays `PUBLIC` by policy. This fallback is only
allowed with `ENVIRONMENT=local`; every other environment refuses to start
without a model, because the rules cannot detect injection.

The legacy single-graph contract remains available via `CLASSIFIER_MODEL_PATH`:
the graph takes `input_ids` (plus `attention_mask` and optional
`token_type_ids`) and returns two logits ordered `[PUBLIC, CONFIDENTIAL]`.
`get_classifier()` is cached per process; a missing graph, tokenizer or digest
mismatch raises `ClassifierConfigurationError` rather than degrading the gate.

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
  tests/test_classifier.py tests/test_classifier_evals.py \
  tests/test_dlp_evals.py tests/test_routing_client.py
```

## Egress Sanitizer & Guarded Chat (Milestone 5)

### Modules

| Module | Responsibility |
|--------|----------------|
| `agent/egress/sanitizer.py` | session canary, untrusted-content fence, output scan, Redis quarantine |
| `gateway/routers/chat.py` | `POST /v1/chat` from ingress audit to sanitized egress |

### What the endpoint does

`POST /v1/chat` is the only path to a model. It requires `operator`, `analyst`
or `admin`, and session-cookie callers must also present the CSRF token. The
stages run in a fixed order and each one is audited before the next starts:

1. `INPUT_RECEIVED` — message count, roles and size; the request itself is
   stored only as a SHA-256 hash.
2. Presidio redaction → `DLP_REDACTION` with entity types and counts.
3. Classification of the **raw** text → `ROUTING_DECISION`. Redaction must not
   run first: a bare IBAN becomes `{{ENTITY:IBAN_CODE_1}}`, which weakens the
   privacy signal (measured 0.582 → 0.201).
4. Canary injection and fencing of `tool` messages as `<untrusted_content>`.
5. Model call on the selected alias.
6. `EGRESS_FILTERED` — canary scan, quarantine check and marker restoration.
   A billed response also writes `SECURITY_INCIDENT` and returns `502` with no
   model text; a quarantined session returns `403` before inference.

Limits are 64 messages, 32,768 characters per message and 65,536 characters per
conversation. `conversation_id` is optional; the response returns the generated
one. The vault session is derived from `actor_id + conversation_id`, so another
principal cannot reuse your id to decode your markers.

```bash
curl -sS http://localhost:8000/v1/chat \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"conversation_id":"demo-1","messages":[{"role":"user","content":"Summarise our Q3 board minutes"}]}'
```

The browser path is **`/dashboard/chat`** (operator/admin): it uses the session
cookie, sends the page's CSRF token, offers four suggested prompts, shows
route/classification badges and restored-marker counts, and links each
conversation to its audit timeline. Each page load gets a fresh conversation id;
`New conversation` rotates it, which is what starts a new vault/canary scope.
Omitting `conversation_id` from the API request also makes the server generate
one.

### Canary and quarantine

Every session gets one `BASTION-CANARY-<uuid4>` in Redis (30-minute TTL) and the marker
is appended to the system instructions with an explicit "never repeat this"
rule. `inspect()` blocks on **any** token with the configured prefix, discards
the response, and quarantines the session for `EGRESS_TRIP_TTL_SECONDS`
(default 900 s). Quarantine is checked before inference on the next turn and is
shared by every gateway replica. Redis is a hard dependency: if it is
unreachable the endpoint returns `503` rather than delivering an unscanned
answer.

A model can also answer "here is the system prompt" and fabricate one. No
marker appears in that text, so the canary cannot see it: the egress stage runs a
deterministic claim detector instead and records `disclosure_claim`
(`system_prompt`, `instructions` or `instructed`) on the `EGRESS_FILTERED` row and
as `bastion.egress.disclosure_claim` on the span. The answer is delivered, not
blocked — the claim is evidence about the model's behaviour, not proof about the
prompt, and a legitimate discussion of prompt engineering must stay answerable.
A silent paraphrase is not detected by either control (ADR-012 decision 9).

### Fencing and restoration

Tool output is wrapped in `<untrusted_content source="…">`, with embedded fence
tags and canary-shaped strings neutralised so a payload cannot close the fence.
After the canary scan, `{{ENTITY:…}}` markers are restored only through the
caller's vault session. A marker whose entry expired stays visible and is
counted; it is never guessed.

### Demo

The canary is deterministic, so the demo feeds the sanitizer the exact text the
egress stage would inspect instead of hoping the model leaks on command:

```bash
uv run python scripts/demo_egress.py
# or inside the app image, against the same Redis and vault key
docker compose exec -T gateway python - < scripts/demo_egress.py
```

It shows the stable per-session marker, a leak blocked with empty delivered text
and the session quarantined, the next turn rejected before inference, a scoped
marker restored, and a tool payload that cannot close its fence. It deletes its
keys afterwards.

For the non-deterministic half — a real model asked to reveal its system prompt —
use the live probe. It prints the raw completion and the gate's verdict; a model
refusal is also a pass, because the invariant is that no canary reaches the
caller:

```bash
LLAMA_CPP_BASE_URL=http://localhost:8002 uv run python scripts/demo_model_canary.py

# inside the app image, against the compose network
docker compose exec -T -e LLAMA_CPP_BASE_URL=http://llama-cpp:8080 \
  gateway python - < scripts/demo_model_canary.py
```

On the pinned model the extraction output is
`raw leak True`, `blocked True (canary_leak)`, `delivered (0 chars)` and
`preflight rejected (circuit_open)`. The probe calls the sanitizer directly, so
it writes no audit rows.

### Verification

```bash
uv run pytest -q tests/test_egress_sanitizer.py tests/test_egress_evals.py \
  tests/test_chat.py tests/test_chat_contract.py
```

Two rollout checks need an external service. The Redis one runs as a gate in CI
(a Redis 7 service is provisioned); locally:

```bash
# Redis TTL expiry, shared canary and quarantine keys (Redis 7)
docker run --rm -d --name bastion-test-redis -p 56379:6379 redis:7-alpine
REDIS_TEST_URL=redis://localhost:56379/0 uv run pytest -m redis_integration

# Real model extraction probe through the sanitizer
LLAMA_CPP_BASE_URL=http://localhost:8002 \
  LLAMA_CPP_API_KEY=dev-only-llama-api-key \
  uv run pytest -m model_integration
```

The model test is the one skip CI allows: there is no GPU inference endpoint on
the runner, so it is run manually as above (and by
`scripts/demo_model_canary.py`).

The model test asserts the invariant, not the model's politeness: a refusal
passes, while a raw marker in the answer must be blocked with `canary_leak`,
delivered as empty text and quarantined.

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
- **Catalog allow-list (ADR-009 Gate 1)**: `docs/tools/v1.json` is the approved
  capability set. A registered tool that is absent from it is hidden from
  `available_tools()` and rejected with JSON-RPC code `-32003` before argument
  validation, RBAC or ticket creation. Gateway and worker startup fail when the
  registry and catalog disagree, an unreadable catalog exposes no tools, and an
  approved ticket whose tool left the catalog is marked `FAILED` with a
  `SECURITY_INCIDENT` instead of running. Refusals (catalog and RBAC) are
  appended to the ledger; the worker commits them in a dedicated transaction,
  because the guarded request transaction rolls back when the guard raises.
- **Filesystem confinement**: built-in file tools resolve paths inside
  `TOOL_WORKSPACE_ROOT`, reject absolute/traversing paths and symlink escapes,
  cap read/write sizes, and write atomically at mode `0600`.

### Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `TOOL_CATALOG_PATH` | `docs/tools/v1.json` | Versioned Gate 1 allow-list |
| `TOOL_WORKSPACE_ROOT` | `/tmp/bastion-workspace` | Confinement root for file tools |
| `TOOL_MAX_READ_BYTES` | `262144` | Read cap |
| `TOOL_MAX_WRITE_BYTES` | `1048576` | Write cap |
| `TOOL_MAX_ARGUMENT_BYTES` | `1048576` | Reject oversized job arguments |
| `TOOL_RESUME_AUTO_ENQUEUE` | `true` | Push resume jobs; the cron sweep is the fallback |
| `ARQ_CONNECTION_TIMEOUT_SECONDS` | `2` | Gateway enqueue connect timeout |

### Verification

```bash
uv run python scripts/validate_tool_catalog.py --check
uv run pytest -q tests/test_tool_catalog.py tests/test_tool_decorator.py tests/test_tool_execution.py
```

Adding a tool is a two-step review: implement it, run
`uv run python scripts/validate_tool_catalog.py --write`, then read the diff —
the catalog change *is* the approval record. `--check` fails when a registered
tool is unapproved or a catalog entry drifted from its definition, and the same
check runs at startup.

---

## Operator Scripts

| Script | Purpose |
|--------|---------|
| `scripts/verify_audit_chain.py` | Recompute the audit hash chain (exit `1` on tamper, `2` if it cannot run) |
| `scripts/validate_tool_catalog.py` | Registry ↔ `docs/tools/v1.json` allow-list; `--write` approves the current set; the same check runs at startup |
| `scripts/validate_rbac.py` | Realm roles/users ↔ code roles ↔ tool requirements; proves four-eyes is possible |
| `scripts/recalculate_dread.py` | Recompute DREAD totals and the risk-priority list; `--check` / `--write` |
| `scripts/update_threat_intel.py` | Query OSV for every registry package in `uv.lock`; writes `artifacts/threat-intel/latest.json` |
| `scripts/run_evals.py` | Run the three golden gates and atomically publish `artifacts/evals/latest.json` |
| `scripts/gate.sh` | Run every gate in a bounded pool (lint, format, types, pylint, tests, policy scripts) and print a metrics table; `--jobs`, `--evals`, `--integration`, `--no-tests`, `--serial`, `--verbose` |
| `scripts/check_classifier_dispatch.py` | Classify five sentinels and publish the host's `reference` / `dispatch_anomaly` verdict (ADR-011) |
| `scripts/demo_egress.py` | Deterministic canary/leak/quarantine/fence demo against the live Redis |
| `scripts/demo_model_canary.py` | Live `llama.cpp` extraction probe through the egress sanitizer (opt-in) |
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
uv run python scripts/run_evals.py
uv run python scripts/validate_tool_catalog.py --check
uv run python scripts/validate_rbac.py
uv run python scripts/recalculate_dread.py --check
uv run pytest -m "not integration"   # unit tests (no database required)
```

`scripts/gate.sh` runs that set in one shot — adding the ruff format check and
the backlog validator — and prints a metrics table plus one verdict line:

```
  step         status      time  detail
  --------------------------------------
  pytest       ok         6m32s  575 passed, 33 skipped, 43 deselected
  pylint       ok         19.8s  rated at 10.00/10
  ...

gate: 10/10 passed · wall 6m40s · sum 7m12s · 1.08x · jobs 4 · slot 6m32s (pytest)
```

`wall` is the elapsed time, `sum` the total work, and the ratio between them is
what the pool bought you; `slot` names the step that set the floor. Steps run in
a bounded pool with pytest first, so the long test run overlaps the
lint/type/policy work instead of queueing behind it. `--jobs N` caps the pool
(`--jobs 1` or `--serial` is the old sequential run). Each run leaves one log per
step plus a `summary.md` (branch, HEAD, dirty count, the table above) under
`artifacts/gate/<run>/`, with `artifacts/gate/latest` pointing at the newest; a
failure prints that step's tail and exits non-zero. `--evals` adds `run_evals.py` — run alone after the pool, because it
drives pytest itself — `--integration` runs the database-backed tests (requires
`TEST_DATABASE_URL`), `--no-tests` skips pytest, `--verbose` streams each step
prefixed with its name.

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

## Observability (Langfuse Cloud + Arize AX + local OpenLit)

The gateway and worker export OTLP/HTTP spans to `otel-collector`. The base
config (`config/otel/otel-collector-config.yaml`) owns the receiver,
processors, both backends, their headers and the retry policy; a second, small
overlay decides which exporters the traces pipeline actually uses. Maps merge
across the two `--config` files while a list replaces the same path, so every
setting lives in one place.

| Overlay (`OTEL_REMOTE_EXPORT_CONFIG`) | Egress |
|---|---|
| `otel-collector-no-export.yaml` (default) | collector log only |
| `otel-collector-openlit.yaml` | collector log + self-hosted OpenLit |
| `otel-collector-export.yaml` | collector log + Langfuse + Arize |

Local-only is the default so a checkout without backend credentials never posts
401s. Enable fan-out by setting it in `.env`, then recreating the collector:

```dotenv
OTEL_REMOTE_EXPORT_CONFIG=otel-collector-export.yaml
```

```bash
docker compose up -d --force-recreate otel-collector
```

To freeze egress again — for example while a backend quota is exhausted — put
the overlay back to `otel-collector-no-export.yaml` and run the same command.
The remote exporters are then absent from the traces pipeline altogether, so
nothing leaves the host and their credentials are never read.

Health probes and the dashboard's polling endpoints (`/api/approvals` every 3 s,
`/api/evals/latest` every 30 s) are excluded from tracing, so an open dashboard
does not burn a backend quota; the four-eyes decision endpoint stays traced.

### What a chat trace contains

Each guarded turn is one trace: the `POST /v1/chat` server span plus a child
`chat <alias>` span for the model call. The child carries the OpenTelemetry
GenAI conventions a backend needs to show model, tokens and cost in its own
dashboard — `gen_ai.system`, `gen_ai.request.model` (the alias's pinned target,
e.g. `gpt-4o-mini`), `gen_ai.response.model` (what actually answered),
`gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`,
`gen_ai.usage.total_tokens` and `gen_ai.usage.cost` (USD, as reported by
OmniRoute in `usage.cost`). Under it sits the instrumented HTTP span for the
actual request — `POST /v1/chat/completions`, with the upstream status code and
the time spent on the wire, so a retry appears as two child spans and a slow
upstream is distinguishable from a slow local guardrail. Only the OmniRoute
client is instrumented; the Keycloak JWKS and token calls are deliberately left
untraced so sign-ins do not add noise to every model turn. The server span
carries the guardrail evidence: `bastion.dlp.*`, `bastion.classification.*`,
`bastion.route*`, `bastion.egress.*` and `gen_ai.conversation.id`.

The alias itself is a routing label, never reported as a model: sending
`cloud-primary` as `gen_ai.request.model` makes every trace look like an
unintended provider swap. `MODEL_LOCAL_PRIMARY` / `MODEL_CLOUD_PRIMARY` mirror
the first target of each OmniRoute combo (`config/omniroute/config.yaml`, pinned
by `tests/test_routing_client.py`), and a genuine failover to the second target
is recorded as `bastion.model.swapped=true` instead of being hidden.

Prompt and completion text is never exported. That is deliberate: traces go to
third parties, and a DLP product that ships the unredacted prompt into a trace
backend has moved the leak rather than stopped it. The vault markers, entity
counts and routing verdict are the auditable evidence; the text stays in the
audit ledger, hashed.

### What a tool trace contains

Tool execution lives in the worker (`arq`), so it is a second trace, exported as
`service.name=bastion-worker`: `tool.execute <name>` when the runtime authorizes
a call — `bastion.tool.name`, `bastion.audit.session_id`, `bastion.tool.status`,
and `bastion.approval.ticket_id` when it suspends — and `tool.resume` when an
approved ticket runs. The four-eyes decision span in the gateway carries the same
`bastion.approval.ticket_id`, so the approval and the execution join on it. The
two cron sweeps (expiry, approved-ticket resume) are deliberately untraced: they
run every 30 s and would be noise. Tool arguments are hashed in the ledger and
never exported.

To fill the trace store and the ledger with realistic traffic before a demo:

```bash
uv run python scripts/demo_traffic.py
uv run python scripts/demo_traffic.py --json | jq -c .
```

Ten turns across three principals: public prompts that may reach the cloud,
prompts carrying identifiers (redaction and restore), two prompts confidential by
content, an instruction-extraction probe, and a three-turn thread that keeps one
conversation id. Each line reports the classification, route and confidence the
classifier produced; the model's text is not printed, only its length.

### Local OpenLit instead of a cloud backend

A self-hosted OpenLit is the unmetered option: traces never leave the host and
its UI stays queryable. Point the collector at the OpenLit OTLP/HTTP port with
`OPENLIT_OTLP_ENDPOINT` / `OPENLIT_OTLP_AUTH` in `.env`, select the OpenLit
overlay, and recreate the collector:

```dotenv
OTEL_REMOTE_EXPORT_CONFIG=otel-collector-openlit.yaml
OPENLIT_OTLP_ENDPOINT=http://host.docker.internal:4320   # OpenLit 4320 -> 4318
OPENLIT_OTLP_AUTH=<OpenLit API key, sent as x-openlit-api-key>
```

```bash
docker compose up -d --force-recreate otel-collector
```

Two things are easy to get wrong. The collector runs in a container while
OpenLit publishes its OTLP port on the host, so the endpoint is
`host.docker.internal`, which `docker-compose.yml` maps explicitly for Linux
(`extra_hosts: host-gateway`). And these variables must not reuse the
`OTEL_EXPORTER_*` names: the app reads `OTEL_EXPORTER_OTLP_ENDPOINT` itself, so a
second definition of it would win for host-run processes and bypass the
collector. OpenLit is a real OTLP collector, so it takes the exporter defaults
(protobuf, gzip) — no `encoding: json` workaround like Arize needs.

### What is not exported

Egress is metered, so the pipeline drops two span classes before any exporter
(`filter/noise` in the base config, covered by `tests/test_otel_config.py`):

| Dropped | Why |
|---|---|
| ASGI send/receive event spans (`GET /docs http send`) | Three per HTTP request at ~0.03 ms each; the server span already carries the latency. |
| Unmatched paths (`http.status_code=404`) | The volume is caller-controlled. |

The 404 rule is not hypothetical. On 2026-11-10 a local client polled
`/v1/models` — a route this gateway does not implement — every 30 s, which is
**~11,500 spans a day** against ~300 of real traffic, and it tripped Arize's
volume limit while Langfuse looked fine. An unauthenticated scanner can do the
same deliberately, so those spans now stop at the collector: a path scan is
visible at the reverse proxy or firewall, which is the layer that owns that
signal, not in a paid trace backend. Dropping them removed 75% of the remaining
volume as well, since each real request previously carried three event spans.

Configure in `.env`:

```dotenv
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_OTLP_ENDPOINT=https://cloud.langfuse.com/api/public/otel  # EU; us./jp./hipaa. for other regions
LANGFUSE_OTLP_AUTH=<base64 of "public_key:secret_key">

ARIZE_OTLP_ENDPOINT=https://otlp.arize.com
ARIZE_SPACE_ID=<space id>
ARIZE_API_KEY=<arize api key>
ARIZE_PROJECT_NAME=bastion-agent        # x-project-name routing header
```

Both endpoints are **base** URLs: the exporter appends `/v1/traces` itself.
Arize punishes the alternative silently, and both traps below were hit here:

- `ARIZE_OTLP_ENDPOINT=https://otlp.arize.com/v1` produces `/v1/v1/traces`,
  which answers `200 ok` and drops the batch — the collector log stays clean.
- Arize's ingest parses JSON but does not gunzip, so the exporter's default gzip
  compression answers `400 … invalid character '\x1f' looking for beginning of
  value` on every batch. The exporter therefore runs with `encoding: json` and
  `compression: none`.

`tests/test_otel_config.py` pins the base URL and those two settings so neither
regression can come back quietly.

Build the Langfuse Basic credential (must be regenerated whenever a key is
rotated — a stale value makes the collector log `401 Unauthorized`):

```bash
python -c "import base64;print(base64.b64encode(b'pk-lf-...:sk-lf-...').decode())"
```

Verify end to end: make a request (`uv run python scripts/demo_traffic.py` drives ten),
then check three things — the collector shows no `Exporting failed` lines, the
spans read back from Langfuse, and `POST https://api.arize.com/v2/spans` (Bearer
API key, `project_id` from `GET https://api.arize.com/v2/projects?space_id=…`)
returns them. The collector log alone is a weak signal: Arize answers `200 ok`
for a batch it discards.

```bash
# Langfuse: read the spans back instead of trusting the UI.
FROM=$(date -u -d '-15 min' +%Y-%m-%dT%H:%M:%SZ); TO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
curl -s -u "$LANGFUSE_PUBLIC_KEY:$LANGFUSE_SECRET_KEY" \
  "$LANGFUSE_BASE_URL/api/public/v2/observations?fields=core,basic,usage,model&fromStartTime=$FROM&toStartTime=$TO" \
  | jq -r '.data[] | "\(.name) \(.type) model=\(.model // "-") tokens=\(.usageDetails.total // "-") cost=\(.totalCost // "-")"'
```

A guarded turn reads `chat cloud-primary GENERATION model=gpt-4o-mini
tokens=119 cost=2.74725e-05`, and `tool.resume` arrives as a `SPAN` row. Two
traps in that API: `GET /api/public/traces` is deprecated and stops answering on
2026-11-16, and asking for `fields=usage` returns `"usage": null` — the numbers
live in `usageDetails` and `totalCost`.

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
# Zero-tolerance golden gates: DLP entity coverage, egress canaries, classifier labels
uv run pytest tests/test_dlp_evals.py tests/test_egress_evals.py \
  tests/test_classifier_evals.py -v

# Reproduce the threshold sweep recorded in ADR-011
uv run python scripts/tune_classifier.py

# Run all gates and publish artifacts/evals/latest.json for GET /api/evals/latest
uv run python scripts/run_evals.py
```

`DLPRedactionMetric`, `EgressCanaryMetric` and the classifier gate are all
scored in-process, so the suite needs no provider credentials.
`run_evals.py` writes the summary atomically and maps each module to its metric.
A gate that executed no tests scores `0.0` and adds a synthetic failure: an
unverified gate is never reported green.

The one exception is the classifier's host verdict. The pinned int8 graphs do
not reproduce on every x86 host — an AVX2-only CPU (AMD EPYC 7763) marks every
benign row `CONFIDENTIAL` at 0.75–0.97 while hosts with `avx512_vnni` agree with
the calibration values (ADR-011). `scripts/check_classifier_dispatch.py`
classifies five golden sentinels before the gate and publishes `reference` or
`dispatch_anomaly`; only for that exact systemic signature do the two ratio
assertions skip and the report record `exempt_gates` instead of a synthetic
failure. A failed row is never exempted, and a partial mismatch (one benign row,
a lost positive) still falls through to the gate. Running the test file directly
ignores the verdict and asserts everything, which is what a developer on a
normal host wants.
