# Security Controls

## Overview

Bastion-Agent implements **deterministic** security controls at every layer. No security decisions are made by the LLM - all controls are platform-enforced, versioned, and auditable.

## Security Layers

| Layer | Control | Implementation |
|-------|---------|----------------|
| **Ingress** | Single FastAPI gateway with OIDC JWT validation | FastAPI + Keycloak OIDC + JWKS cache |
| **DLP** | Two-stage Presidio + ONNX classifier + Redis vault | Presidio analyzer/anonymizer → ONNX classifier → reversible AES-256-GCM tokenization |
| **Tool Governance** | Four-gate runtime model | Tool catalog allow-list → JWT RBAC → four-eyes HITL approval → source-side entitlement |
| **Egress** | Canary tripwires + XML fence isolation | Session-unique canary tokens embedded in system prompt |
| **Audit** | Append-only PostgreSQL audit with SHA-256 hash chaining | `audit_logs` table with cryptographic chain verification |
| **Observability** | OpenTelemetry → Langfuse/Arize/BetterStack | OTel Collector exports OTLP/HTTP spans with redaction allowlist |

## Key Controls

### Two-Stage DLP Pipeline

1. **Microsoft Presidio**: Entity detection (PERSON, EMAIL_ADDRESS, PHONE_NUMBER, IBAN_CODE, CREDIT_CARD, US_SSN, plus Swiss-specific types)
2. **ONNX Classifier**: Semantic sensitivity detection for confidential business content
3. **Redis Token Vault**: AES-256-GCM encrypted reversible tokenization (30-min TTL)

### Confidentiality Routing

- **Secret prompts** → Local `llama.cpp` (Qwen 2.5 7B on RTX 3060 Ti)
- **General prompts** → Cloud providers via OmniRoute
- **No cloud egress** for sensitive data

### Four-Eyes HITL Governance

- State-changing tools (`read_only=False`) require secondary operator approval
- `approver_id != initiator_id` enforced at database level
- Approval binding: single-use, exact-action hash, expires automatically

### Egress Canary Tripwires

- Unique `BASTION-CANARY-<uuid4>` embedded in system prompt per session
- Egress filter scans all tool outputs for canary presence
- Circuit breaker trips; response blocked if canary detected

### Tamper-Evident Audit Ledger

```sql
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    session_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    payload_hash BYTEA NOT NULL,
    previous_hash BYTEA NOT NULL,
    record_hash BYTEA NOT NULL  -- SHA-256 chain
);
```

### Role-Based Access Control

| Role | Permissions |
|------|-------------|
| `admin` | Full system access |
| `operator` | Execute state-changing tools |
| `analyst` | Read-only data access |
| `readonly` | Read-only, no tool execution |

---
*This wiki is synchronized from the docs/ directory of the main repository.*
