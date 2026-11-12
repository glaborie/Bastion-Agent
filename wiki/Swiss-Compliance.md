# Swiss Compliance

> **Bastion-Agent: Swiss Market Reference Architecture**
> For regulated enterprises, banks, insurers, and healthcare in Switzerland

## Why Bastion-Agent for the Swiss Market?

Switzerland has some of the **strictest data protection laws** in the world:

- **FINMA Circular 2018/3** (Outsourcing)
- **GDPR** (General Data Protection Regulation)
- **Swiss Banking Act** (SR 954.1) — banking secrecy
- **Swiss Data Protection Act** (revised)
- **EU AI Act** (High-Risk AI Systems)
- **SOC 2 Type II**

Bastion-Agent is **designed from the ground up** for Swiss-regulated environments.

## Regulatory Alignment

| Regulation | Alignment | Evidence |
|------------|-----------|----------|
| **FINMA Circular 2018/3** | Tool governance, audit trail, kill switch tiers, deterministic controls | ADR-009 §4.2, ADR-005, Tier 1/2/3 |
| **GDPR Art. 32** | DLP, reversible tokenization, data minimization, audit trail | ADR-002, ADR-005, OTel redaction |
| **Swiss Banking Act Art. 47** | Tool catalog allow-list, four-eyes approval, source-side entitlement | ADR-009, Gate 1/2/3/4 |
| **SOC 2 Type II** | Non-repudiable audit logs, change control, regression gates | ADR-005, ADR-006, CI gating |
| **EU AI Act** | Fail-closed design, deterministic controls, auditability | ADR-001, ADR-009 |

## Swiss-Specific Security Controls

### 1. Data Residency by Design

- **Confidential prompts** → Local `llama.cpp` (Qwen 2.5 7B on RTX 3060 Ti)
- **General prompts** → Cloud providers via OmniRoute
- **No cloud egress** for sensitive data

### 2. Banking Secrecy Enforcement

- **Tool catalog allow-list** (`docs/tools/v1.json`) with `require_approval` per tool
- **Four-eyes HITL approval** for state-changing tools
- **Source-side entitlement** — tool implementation validates tenant

### 3. Compliance Features

- **SHA-256 hash-chained audit logs** for non-repudiation
- **Tamper-evident evidence ledger** with Ed25519 run certificates
- **DeepEval regression gates** with 100% recall requirement
- **SBOM publication** for supply chain transparency

---
*This wiki is synchronized from the docs/ directory of the main repository.*
