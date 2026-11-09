# CONTROL.md — Command Control Center Extended Specification

This document defines the full feature set for the Bastion-Agent Command Control Center (HTMX dashboard served at `/dashboard`). It extends the core approval queue and eval health card from `HANDOVER_SPEC.md`.

---

## High-Value Features (Priority 1)

### 1. Live Session Inspector
**Route**: `/dashboard/sessions/{session_id}`
**Purpose**: Full conversation forensics for incident investigation.

**Tabs/Views**:
- **Timeline**: Chronological event stream with expandable cards:
  - `INPUT_RECEIVED`: Raw prompt (PII masked, toggle to reveal with audit permission)
  - `DLP_REDACTION`: Side-by-side diff (original → tokenized)
  - `ROUTING_DECISION`: Classifier confidence, model alias selected (`local-llama` / `cloud-primary`)
  - `TOOL_REQUESTED`: Tool name, arguments, read_only flag, required_role
  - `APPROVAL_GRANTED/REJECTED`: Approver ID, timestamp, HMAC verification status
  - `EGRESS_FILTERED`: Canary tripwire trigger or clean pass
  - `RESPONSE_SENT`: Final output (detokenized for authorized viewer)

- **Raw JSON**: Complete `AuditLog` records for the session with hash chain verification.

**Actions**:
- "Export Session" → JSONL (sanitized or full based on role)
- "Replay in Sandbox" → Re-execute with same inputs in isolated test mode

---

### 2. Audit Log Explorer
**Route**: `/dashboard/audit`
**Purpose**: Compliance-grade search and integrity verification.

**Features**:
- **Filter Panel**: `event_type` multi-select, `actor_id` search, date range picker, `session_id` exact match
- **Pagination**: Server-side, 50 rows/page, cursor-based
- **Columns**: Timestamp, Event Type, Actor, Session, Payload Hash (truncated), Prev Hash (truncated), Record Hash (truncated)
- **Row Expansion**: Full `metadata_json` pretty-printed
- **Integrity Verification**:
  - "Verify Chain" button → Background job recomputes `record_hash` for visible range (or full table)
  - Results: `✅ Intact` / `❌ Tampered at ID {id}` with diff
- **Export**: CSV/JSONL with optional hash column inclusion

---

### 3. Token Vault Browser
**Route**: `/dashboard/vault`
**Purpose**: Inspect and manage active reversible token mappings.

**Table Columns**:
- Session ID (link to Session Inspector)
- Token (e.g., `{{ENTITY:PERSON_1}}`)
- Entity Type (PERSON, EMAIL, API_KEY, etc.)
- Masked Value (`Al***`, `sk-***`, `+41 ** *** ** **`)
- TTL Remaining (live countdown, red when < 5 min)
- Created At

**Actions**:
- "Force Expire" → Deletes Redis key immediately
- "Extend TTL" → +30 min (operator only)
- "View Decrypted" → Requires `admin` role + MFA confirmation (audit logged)

---

### 4. DLP Rule Manager
**Route**: `/dashboard/dlp/rules`
**Purpose**: Manage Presidio recognizers and custom deny/allow patterns without code deploy.

**Tabs**:
- **Presidio Recognizers**: Toggle built-in (PERSON, EMAIL, PHONE, IBAN, IP, CREDIT_CARD, etc.)
- **Custom Patterns**: Regex-based deny/allow lists with test harness
  - Fields: Name, Regex, Action (DENY/ALLOW/REDACT), Entity Type, Description
  - "Test Pattern" modal: Paste sample text → shows matches + replacement preview

**Persistence**: Writes to `config/dlp/rules.yaml` (mounted in gateway container, hot-reloaded).

---

### 5. Model Routing Dashboard
**Route**: `/dashboard/routing`
**Purpose**: Real-time observability of OmniRoute traffic split.

**Metrics Cards** (auto-refresh 10s):
- **Traffic Split**: Donut chart `% local-llama` vs `% cloud-primary`
- **Latency**: p50 / p95 / p99 per route (ms)
- **Error Rate**: 5xx / timeout / circuit-open per route
- **Cost Estimate**: OpenRouter credits consumed (last 1h / 24h / 7d)
- **Local GPU Util**: RTX 3060 Ti VRAM %, GPU % (via `nvidia-smi` sidecar)

**Table**: Recent routing decisions (last 100) with prompt hash, classification confidence, route, latency.

---

### 6. Canary Tripwire Log
**Route**: `/dashboard/security/canary`
**Purpose**: Every egress filter trigger — the "red phone" for prompt injection attempts.

**Columns**:
- Timestamp, Session ID, Trigger Type (`CANARY_LEAK`, `INJECTION_HEURISTIC`, `UNTRUSTED_CONTENT_ESCAPE`)
- Prompt Snippet (first 200 chars, sanitized)
- Model Output Excerpt (where canary detected)
- Action Taken (`BLOCKED`, `QUARANTINED`, `ALERT_ONLY`)
- Actor ID (initiator)

**Actions**:
- "View Full Session" → Links to Session Inspector
- "Block Actor" → Revokes Keycloak session / adds to deny list (admin only)
- "Export for SOC" → Structured JSON for SIEM ingestion

---

### 7. RBAC Matrix Visualizer
**Route**: `/dashboard/rbac`
**Purpose**: Declarative policy management for tool access.

**Grid View**:
- Rows: Tools (from `@tool` registry + builtins)
- Columns: Roles (`admin`, `operator`, `analyst`, `readonly`)
- Cells: Badge — `✅ Allow` / `🔒 Requires Approval` / `❌ Deny`

**Inline Editing**:
- Click cell → Dropdown to change policy
- "Save Changes" → Validates no circular deps, writes to `config/rbac/policy.yaml`, hot-reloads gateway

**Audit**: Every change logged to `audit_logs` with `event_type: RBAC_POLICY_CHANGE`.

---

### 8. Worker Health & Control
**Route**: `/dashboard/workers`
**Purpose**: ARQ queue and worker observability.

**Panels**:
- **Queue Depth**: Pending / Active / Deferred / Failed (live counters)
- **Active Jobs**: Table — Job ID, Function, Session ID, Started At, Duration, Try #
- **Stuck Jobs**: Filter `duration > 300s` with "Cancel" / "Retry" actions
- **Worker Processes**: PID, Started, Jobs Processed, Memory %, CPU %
- **Controls**: "Pause Enqueue" (drain mode), "Resume", "Graceful Shutdown"

---

## Nice-to-Have Features (Priority 2)

### 9. Theme & UX Polish
- **Dark/Light Toggle**: Tailwind `dark:` variant + `localStorage` persistence
- **WebSocket Live Updates**: Replace 3s polling with `hx-ext="ws"` for approval queue, worker health, routing metrics
- **Keyboard Shortcuts**:
  - `a` → Approve selected
  - `r` → Reject selected
  - `/` → Focus global search
  - `?` → Show shortcuts modal
- **Command Palette** (`Ctrl+K`): Jump to any route, search sessions, actors, tools

---

### 10. Session Replay (Sanitized)
**Route**: `/dashboard/sessions/{session_id}/replay`
**Purpose**: Step-through reconstruction of agent execution for debugging.

- Timeline scrubber with play/pause
- Each step shows: Input → DLP → Route → Tool(s) → Approval → Output
- PII auto-masked; "Reveal" requires `admin` + MFA
- "Fork to Test" → Creates new test case in `tests/data/goldens.jsonl` from this session

---

### 11. Audit Slice Export
**Route**: `/dashboard/audit/export`
**Purpose**: Compliance handoff package.

- Date range + event type filter
- Output formats: CSV, JSONL, PDF (with hash chain verification appendix)
- Digital signature: SHA-256 of export + timestamp, signed by service key
- One-click "Prepare for Auditor" → Generates zip with manifest + README

---

### 12. Configuration Drift Detection
**Route**: `/dashboard/config/drift`
**Purpose**: Detect runtime config vs git-tracked config mismatch.

- Compares: `config/dlp/rules.yaml`, `config/rbac/policy.yaml`, `config/omniroute/config.yaml`, Keycloak realm JSON
- Shows: `✅ Synced` / `⚠️ Drift detected` / `❌ Missing in git`
- "Sync to Git" → Creates PR with changes (requires GitHub App token)

---

## Implementation Notes

### Tech Stack
- **Frontend**: HTMX 2.x + Alpine.js (for modals/toggles) + Pico.css (lightweight, no build step)
- **Templates**: Jinja2 (FastAPI `Jinja2Templates`)
- **Static**: Served via FastAPI `StaticFiles` at `/static`
- **WebSockets**: `fastapi.WebSocket` + `hx-ext="ws"` (native, no Socket.io)
- **Auth**: Same JWT dependency as API; dashboard routes protected by `require_roles(["operator", "admin"])`

### Data Access
- All dashboard data via internal API routes (`/api/*`) — no direct DB/Redis access from templates
- API routes reuse existing service layers (audit service, vault service, routing service)

### Mounting in Compose
```yaml
# docker-compose.yml (gateway service)
volumes:
  - ./gateway/dashboard/templates:/app/gateway/dashboard/templates:ro
  - ./gateway/dashboard/static:/app/gateway/dashboard/static:ro
  - ./config/dlp:/app/config/dlp:ro
  - ./config/rbac:/app/config/rbac:ro
```

---

## API Endpoints Summary (for Dashboard)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/approvals` | Pending approvals (polling) |
| POST | `/api/approvals/{id}/action` | Approve/Reject |
| GET | `/api/evals/latest` | Last DeepEval run summary |
| GET | `/api/sessions/{id}/timeline` | Session Inspector data |
| GET | `/api/audit` | Paginated audit logs |
| POST | `/api/audit/verify` | Trigger hash chain verification |
| GET | `/api/vault` | Active token mappings |
| POST | `/api/vault/{session_id}/expire` | Force expire session vault |
| GET | `/api/dlp/rules` | Current DLP rules |
| POST | `/api/dlp/rules` | Update DLP rules |
| GET | `/api/routing/metrics` | Routing dashboard metrics |
| GET | `/api/security/canary` | Canary tripwire log |
| GET | `/api/rbac/matrix` | RBAC policy grid |
| POST | `/api/rbac/matrix` | Update RBAC policy |
| GET | `/api/workers/health` | ARQ queue + worker stats |
| POST | `/api/workers/control` | Pause/Resume/Shutdown |

---

## Rollout Phasing

| Phase | Features | Target |
|-------|----------|--------|
| **MVP** (Milestone 2) | Approval Queue, Eval Health, Session Inspector (basic), Audit Explorer (basic) | Week 1-2 |
| **Phase 1** | Token Vault, DLP Rule Manager, Routing Dashboard, Canary Log | Week 3-4 |
| **Phase 2** | RBAC Matrix, Worker Health, Theme/WS, Keyboard Shortcuts | Week 5-6 |
| **Phase 3** | Session Replay, Audit Export, Config Drift | Week 7-8 |

---

## Security Considerations

- **No PII in Dashboard by Default**: All entity values masked; "Reveal" requires `admin` role + step-up auth (TOTP/WebAuthn)
- **Audit Every View**: `AUDIT_LOG_VIEW` event logged with viewer identity
- **CSRF Protection**: All mutating endpoints require `X-CSRF-Token` header (issued on dashboard load)
- **Rate Limiting**: Dashboard API: 60 req/min per user (stricter than chat API)
- **Content Security Policy**: Strict CSP headers, no inline scripts except HTMX/Alpine nonce
