# SECURITY.md

> **Bastion-Agent Security Policy**
> Last updated: 2026-11-09  
> Version: 1.0  
> Owner: AI Platform Team  
> Classification: **Internal Use Only**

---

## 🔐 Overview

Bastion-Agent is a **high-assurance, zero-trust AI agent harness** designed for **Swiss-regulated environments** (FINMA, GDPR, Swiss Banking Act). It enforces **deterministic security controls** at every layer: ingress, DLP, tool governance, egress, and audit. **No security decision is made by the model.** All controls are platform-enforced, versioned, and auditable.

---

## 🛡️ Security Controls by Layer

| Layer | Control | Implementation | Swiss Relevance |
|-------|---------|----------------|------------------|
| **Ingress** | Single FastAPI gateway with OIDC JWT validation | FastAPI + Keycloak OIDC + JWKS cache | Prevents unauthorized access; enforces identity at the choke point |
| **DLP** | Two-stage Presidio + ONNX classifier + Redis vault | Presidio analyzer/anonymizer → ONNX classifier → reversible tokenization in Redis (AES-256-GCM, 30-min TTL); any prompt where DLP finds personal data is kept on the local model | Prevents PII/secrets from reaching a third-party model; supports Swiss data residency |
| **Tool Governance** | Four-gate runtime model (occludra + Microsoft patterns) | Tool catalog allow-list → JWT RBAC → four-eyes HITL approval → source-side entitlement | Enforces least privilege, segregation of duties, and auditability |
| **Egress** | Canary tripwires + XML fence isolation | Session-unique canary tokens embedded in system prompt; tool outputs scanned before return | Detects and blocks indirect prompt injection and data exfiltration |
| **Audit** | Append-only PostgreSQL audit with SHA-256 hash chaining | `audit_logs` table with `record_hash` = SHA256(id || timestamp || actor_id || event_type || payload_hash || previous_hash) | Non-repudiable logs for Swiss compliance audits |
| **Observability** | OpenTelemetry → Langfuse/Arize/BetterStack | OTel Collector exports OTLP/HTTP spans with redaction allowlist | Data minimization for Swiss privacy laws |

---

## 🔐 Authentication & Authorization

### Authentication
- **Protocol**: OpenID Connect (OIDC) 1.0 / OAuth 2.0
- **Provider**: Keycloak (self-hosted, private-by-default)
- **Token Type**: RS256/ES256 JWT
- **Validation**: JWKS cache at FastAPI ingress
- **Claims**: `sub`, `realm_access.roles`, `preferred_username`

### Authorization
- **Roles**: `admin`, `operator`, `analyst`, `readonly`
- **Tool-level**: `@tool(required_role="operator")` decorator
- **Data-level**: Tool implementation validates `AgentContext.user_roles` against data scope
- **Four-eyes HITL**: State-changing tools (`read_only=False`) require separate operator approval
- **Approval binding**: Single-use, exact-action hash, expires, `approver_id != initiator_id`

### Kill Switch Tiers
| Tier | Action | Owner | Evidence |
|------|--------|-------|----------|
| **Tier 1** | Detach write toolset | AI Platform Team | Toolbox version history |
| **Tier 2** | Disable identity or revoke app role | Identity Team | Entra sign-in logs, PIM activations |
| **Tier 3** | Disable account | Security Operations | `accountEnabled` flag, access reviews |

---

## 🔐 Data Protection & DLP

### PII & Secret Detection
- **Engine**: Microsoft Presidio (analyzer + anonymizer)
- **Categories**: PERSON, EMAIL_ADDRESS, PHONE_NUMBER, IBAN_CODE, IP_ADDRESS, CREDIT_CARD, US_SSN, plus three local shape recognizers: API_KEY (provider tokens and secret assignments), ADDRESS (street + postal code + place) and DATE_OF_BIRTH (a date with an explicit birth anchor). Recall is bounded by this list and by the English NER model; see ADR-002 decision 5
- **Patterns**: Regex + Presidio recognizers
- **Redaction**: Reversible tokenization (`{{ENTITY:PERSON_1}}`)

### Reversible Token Vault
- **Storage**: Redis (AES-256-GCM encrypted)
- **TTL**: 30 minutes
- **Session key**: `vault:{session_id}`
- **Access**: Only authorized client can detokenize
- **No plaintext PII** in audit logs or model outputs

### Canary Injection
- **Mechanism**: Session-unique `BASTION-CANARY-<uuid4>` in system prompt
- **Detection**: Egress filter scans tool outputs for canary presence
- **Response**: Circuit breaker trips; response blocked

---

## 🔐 Tool Governance & RBAC

### Tool Catalog
- **Format**: `docs/tools/v1.json` (immutable, versioned)
- **Discovery**: `@tool` decorator + entry points
- **Allow-list**: Agent sees only tools in current catalog version
- **Approval policy**: `require_approval: true` per tool
- **Error code**: `-32003` for tools outside catalog

### Four-Gate Runtime Model
1. **Gate 1: Tool catalog allow-list**
   - Toolbox version pinning
   - Separate read-only and write toolsets
   - `require_approval` declared per tool
2. **Gate 2: Connection identity and RBAC**
   - Entra Agent ID / Keycloak JWT validation
   - App roles (`MCP.Tools.Read`, `MCP.Tools.Operate`)
   - Operator roles time-bound and sponsored
3. **Gate 3: Human approval**
   - ARQ suspension → `PendingApproval` record
   - Approval via `/api/approvals/{id}/action`
   - `approver_id != initiator_id`
4. **Gate 4: Source-side entitlement**
   - Tool implementation validates token claims
   - Untrusted output framing
   - Egress canary tripwires

### Request Context ≠ Authorization
- **Rule**: Treat everything in agent request context as tainted input
- **Authorization**: Derived only from verified identity
- **Re-check**: At every tool and resource boundary
- **Model**: Never the policy decision point

---

## 🔐 Audit & Non-Repudiation

### Audit Log Schema (PostgreSQL)
```sql
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    session_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    event_type TEXT NOT NULL,  -- INPUT_RECEIVED, DLP_REDACTION, ROUTING_DECISION, TOOL_REQUESTED, APPROVAL_GRANTED, EGRESS_FILTERED, RBAC_POLICY_CHANGE
    payload_hash BYTEA NOT NULL,
    metadata_json JSONB,
    previous_hash BYTEA NOT NULL,
    record_hash BYTEA NOT NULL  -- SHA-256(id || timestamp || actor_id || event_type || payload_hash || previous_hash)
);
```

### Verification
- **Endpoint**: `/api/audit/verify`
- **Mechanism**: Recompute hash chain for a given range
- **Retention**: 7 years (partitioned by year)
- **Cold storage**: Migrate to archival after 1 year

### Evidence Ledger & Run Certificate
- **Ledger**: Append-only, digest-only records
- **Run certificate**: Ed25519-signed certificate binding ledger head + artifact digest + approvals
- **Completion**: Run valid only with non-withheld certificate

---

## 🔐 Prompt Injection & Egress Defense

### Injection Detection
- **Presidio**: Mid-context override, system-prompt extraction, refusal suppression
- **Canary tokens**: Session-unique strings embedded in system prompt
- **Egress filter**: Scans tool outputs for canary presence before return

### Indirect Prompt Injection
- **Mechanism**: Untrusted tool output or retrieved context
- **Defense**: XML fence isolation + canary tripwires + egress scanning
- **Response**: Circuit breaker trips; response blocked

### Fail-Closed by Default
- **Policy**: If safety layer is down, requests are blocked, never forwarded unscanned
- **Health checks**: FastAPI `/health/ready` blocks traffic until Presidio, classifier, Redis, and OmniRoute are healthy

---

## 🔐 Observability & Telemetry

### OpenTelemetry Exporters
- **Langfuse Cloud**: `https://cloud.langfuse.com/api/public/otel` (EU region)
- **Arize AX**: `https://otlp.arize.com` (base URL; the exporter appends `/v1/traces`)
- **Better Stack**: OTLP/HTTP endpoint

### Data Minimization
- **Redaction allowlist**: Only span names, durations, error types
- **No prompts**: Prompts, tool args, retrieved content, model outputs **never** exported
- **Hashing**: Identifiers hashed before export

### Collector Configuration
- **Image**: `otel/opentelemetry-collector-contrib:latest`
- **Ports**: `4317` (gRPC), `4318` (HTTP), `8888` (metrics), `8889` (health)
- **Health check**: `/health` endpoint

---

## 🔐 Compliance & Regulatory Alignment

| Regulation | Alignment | Evidence |
|------------|-----------|----------|
| **FINMA Circular 2018/3** (Outsourcing) | Tool governance, audit trail, kill switch tiers | ADR-009 §4.2, ADR-005, Tier 1/2/3 |
| **GDPR** (Art. 32 Security of Processing) | DLP, reversible tokenization, data minimization, audit trail | ADR-002, ADR-005, OTel redaction |
| **Swiss Banking Act** (Art. 47 Secrecy) | Tool catalog allow-list, four-eyes approval, source-side entitlement | ADR-009, Gate 1/2/3/4 |
| **SOC 2 Type II** | Non-repudiable audit logs, change control, regression gates | ADR-005, ADR-006, CI gating |
| **EU AI Act** (High-Risk AI Systems) | Fail-closed design, deterministic controls, auditability | ADR-001, ADR-009 |

---

## 🔐 Incident Response

### Escalation Path
1. **Tier 1 (AI Platform Team)**: Tool catalog, approval workflow, dashboard
2. **Tier 2 (Identity Team)**: JWT validation, RBAC, kill switch Tier 2
3. **Tier 3 (Security Operations)**: Audit trail, kill switch Tier 3, SOC 2 incident response

### Containment
- **Kill switch**: Disable identity, detach toolset, revoke app role
- **Quarantine**: Isolate affected agent run in ARQ worker
- **Evidence preservation**: Hash-chained audit logs preserved for investigation

### Communication
- **Internal**: `#ai-platform-security` Slack channel
- **Customer**: Security incident report within 24 hours (FINMA requirement)
- **Regulator**: Report within 72 hours if customer data exposed

---

## 🔐 Secure Development Lifecycle

### Code Review
- **ADRs**: Required for every architectural change
- **Tool declarations**: `@tool` decorator with `required_role` and `read_only`
- **DLP rules**: Presidio recognizers and regex patterns reviewed by security team

### Testing
- **Unit tests**: `pytest -m "not integration"` (ruff + mypy --strict clean)
- **Integration tests**: Disposable PostgreSQL + Redis
- **Golden regression suite**: `tests/data/goldens.jsonl` + DeepEval (threshold 1.0)
- **Penetration testing**: Quarterly red team exercises

### CI/CD Gates
- **DLP recall**: 100% on every entity type asserted in `tests/data/goldens.jsonl`; recall outside the configured entity list is not claimed (ADR-002 decision 5)
- **Approval workflow**: All state-changing tools require approval
- **Audit chain**: Hash chain verification before merge
- **Image pinning**: All third-party images pinned by digest

---

## 🔐 Deployment Security

### Docker Compose Hardening
- **Images**: Pinned by digest
- **Capabilities**: `cap_drop: [ALL]`, `no-new-privileges`
- **Root filesystem**: Read-only where possible
- **Network**: Internal Docker network, no host exposure
- **Ports**: Bound to `127.0.0.1` (use TLS reverse proxy for external access)
- **Volumes**: Read-only mounts for models and configs

### Secrets Management
- **Environment variables**: `.env` file (never committed)
- **Key rotation**: Quarterly rotation for `LLAMA_API_KEY`, `OPENROUTER_API_KEY`, `REDIS_PASSWORD`
- **Vault**: Use HashiCorp Vault or Azure Key Vault for production

### Health & Readiness
- **Gateway**: `/health`, `/health/ready`
- **Presidio**: `/health`
- **Redis**: `/health`
- **OmniRoute**: `/health`
- **Fail-closed**: If any health check fails, block traffic

---

## 🔐 Third-Party Dependencies

| Dependency | Version Pin | Vulnerability Scanning | Swiss Relevance |
|------------|-------------|------------------------|------------------|
| **Presidio** | Latest stable | Snyk, CodeQL | PII/secrets detection |
| **Redis** | 7.x | CVE database | Token vault storage |
| **PostgreSQL** | 16.x | CVE database | Audit log storage |
| **llama.cpp** | Latest GGUF-compatible | CVE database | Local inference |
| **OmniRoute** | Latest | CVE database | Model routing |
| **OpenTelemetry Collector** | Latest contrib | CVE database | Observability |

### Vulnerability Management
- **Scanning**: Weekly Snyk scans
- **Patching**: Critical CVEs patched within 7 days
- **SBOM**: Software Bill of Materials generated per release

---

## 🔐 Contact & Reporting

### Security Team
- **Slack**: `#ai-platform-security`
- **Email**: security@bastion-agent.ai
- **PGP**: [PGP Key ID] (published on company website)

### Reporting a Vulnerability
1. **Email**: security@bastion-agent.ai (PGP-encrypted)
2. **Include**: Description, reproduction steps, impact, suggested fix
3. **Response**: Acknowledgment within 24 hours, fix within 7 days (critical), 30 days (moderate)

### Public Disclosure
- **Policy**: 90-day coordinated disclosure window
- **Process**: CVE assigned, advisory published, patches released

---

## 🔐 References

- [FINMA Circular 2018/3 – Outsourcing](https://www.finma.ch/en/~/media/finma/dokumente/dokumentencenter/myfinma/1aussenstellen/20180827_circ_18_03_e.pdf)
- [GDPR Art. 32 – Security of Processing](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679)
- [Swiss Banking Act (SR 954.1)](https://www.fedlex.admin.ch/eli/cc/1934/577_581_583/en)
- [EU AI Act – High-Risk AI Systems](https://artificialintelligenceact.eu/)
- [Microsoft Enterprise Agent Security and Tool Governance](https://github.com/microsoft/agenticai-design-patterns)
- [Occludra AI Security Gateway](https://github.com/occludra/gateway)

---

## 🔐 Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-11-09 | Initial release | AI Platform Team |

---

## 🔐 License

Bastion-Agent is licensed under the **MIT License**. Security policy is **Internal Use Only**.

---

**File saved:** `SECURITY.md` in Bastion-Agent project root

**Purpose:** To be referenced in compliance audits, customer security questionnaires, and internal security reviews.