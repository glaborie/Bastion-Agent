# COMPLIANCE.md

> **Bastion-Agent Compliance Matrix**
> Last updated: 2026-11-09  
> Version: 1.0  
> Owner: AI Platform Team  
> Classification: **Internal Use Only**

---

## 📋 Executive Summary

Bastion-Agent is designed for **Swiss-regulated environments** and aligns with **FINMA**, **GDPR**, **Swiss Banking Act**, **SOC 2 Type II**, and **EU AI Act** requirements. This document maps each architectural decision (ADR) to specific regulatory clauses and provides evidence for customer security questionnaires and compliance audits.

---

## 🏛️ Regulatory Framework

| Regulation | Scope | Applicability | Bastion-Agent Alignment |
|------------|-------|---------------|--------------------------|
| **FINMA Circular 2018/3** | Outsourcing of services | ✅ Applicable | Tool governance, audit trail, kill switch tiers, deterministic controls |
| **GDPR** (Art. 32) | Security of processing | ✅ Applicable | DLP, reversible tokenization, data minimization, audit trail, consent tracking |
| **Swiss Banking Act** (SR 954.1) | Banking secrecy | ✅ Applicable | Tool catalog allow-list, four-eyes approval, source-side entitlement, non-repudiation |
| **SOC 2 Type II** | Security, availability, processing integrity, confidentiality, privacy | ✅ Applicable | Non-repudiable audit logs, change control, regression gates, incident response |
| **EU AI Act** | High-risk AI systems | ✅ Applicable | Fail-closed design, deterministic controls, auditability, transparency |
| **Swiss Data Protection Act (revised)** | Data processing and privacy | ✅ Applicable | PII redaction, reversible tokenization, data minimization, audit trail |

---

## 🔗 ADR-to-Regulation Mapping

| ADR | Regulation Clause | Evidence | Compliance Status |
|-----|-------------------|----------|-------------------|
| **ADR-001: Core Ingress & Zero-Trust Gateway** | FINMA 2018/3 §4.2 (Outsourcing), GDPR Art. 32, EU AI Act Art. 10 | Single FastAPI ingress, OIDC JWT validation, deterministic DLP, OmniRoute routing, hash-chained audit | ✅ Compliant |
| **ADR-002: Two-Stage DLP & Reversible Token Vault** | GDPR Art. 32, Swiss Banking Act Art. 47, EU AI Act Annex III | Presidio + ONNX classifier + Redis vault, reversible tokenization, canary injection | ✅ Compliant |
| **ADR-003: Declarative RBAC & Four-Eyes HITL** | FINMA 2018/3 §4.3 (Segregation of Duties), Swiss Banking Act Art. 47, SOC 2 Type II (Access Controls) | JWT role extraction, `@tool` decorator with `required_role`, ARQ suspension, approval workflow | ✅ Compliant |
| **ADR-004: OmniRoute Model Routing & Failover** | FINMA 2018/3 §4.2 (Outsourcing), GDPR Art. 44-49 (Data Transfers) | Local fallback to llama.cpp, cloud routing via OmniRoute, fail-closed design | ✅ Compliant |
| **ADR-005: Cryptographic Audit Trail & Hash Chaining** | FINMA 2018/3 §4.5 (Audit Trail), GDPR Art. 30 (Records of Processing), SOC 2 Type II (Logging) | PostgreSQL `audit_logs` with SHA-256 `record_hash` chaining, verification endpoint | ✅ Compliant |
| **ADR-006: DeepEval Golden Dataset & Regression Gating** | SOC 2 Type II (Change Control), GDPR Art. 32 (Security Testing), EU AI Act Art. 15 (Risk Management) | `goldens.jsonl` with 25+ categories, Pytest + DeepEval, CI gate at 1.0 recall | ✅ Compliant |
| **ADR-007: Command Control Dashboard & HTMX Integration** | FINMA 2018/3 §4.4 (Monitoring), SOC 2 Type II (Monitoring) | FastAPI + Jinja2 + HTMX + Pico.css dashboard, real-time approvals, audit explorer | ✅ Compliant |
| **ADR-008: Evolution Roadmap & Version Policy** | FINMA 2018/3 §4.6 (Change Management), SOC 2 Type II (Change Management) | 6-phase roadmap (v0.1→v0.6), semantic versioning, drop-in Docker Compose upgrades | ✅ Compliant |
| **ADR-009: Four-Gate Tool Governance Model** | FINMA 2018/3 §4.3 (Segregation of Duties), Swiss Banking Act Art. 47, EU AI Act Art. 10 | Four serial runtime gates, request context ≠ authorization, bounded autonomy, evidence ledger | ✅ Compliant |

---

## 📊 Compliance Evidence Matrix

| Requirement | Evidence Source | Bastion-Agent Implementation | Status |
|-------------|-----------------|-------------------------------|--------|
| **Non-repudiable audit trail** | ADR-005, `SECURITY.md` §Audit & Non-Repudiation | PostgreSQL `audit_logs` with SHA-256 `record_hash` chaining, verification endpoint `/api/audit/verify` | ✅ Implemented |
| **Runtime detection** | ADR-017, `SECURITY.md` §Incident Response | Opt-in Falco syscall rules for shells, workspace escapes, egress and sensitive writes; JSON alerts in `artifacts/falco/` | ⚠️ Partial (opt-in) |
| **Deterministic authorization** | ADR-009, `SECURITY.md` §Tool Governance & RBAC | Four-gate runtime model, JWT RBAC, tool catalog allow-list, source-side entitlement | ✅ Implemented |
| **Least privilege access** | ADR-003, ADR-009, `SECURITY.md` §Authentication & Authorization | Four-tier roles (`admin`, `operator`, `analyst`, `readonly`), `@tool(required_role="operator")`, read-only allow list | ✅ Implemented |
| **Segregation of duties** | ADR-003, ADR-009, `SECURITY.md` §Kill Switch Tiers | Four-eyes HITL approval, `approver_id != initiator_id`, time-bound operator roles | ✅ Implemented |
| **Data minimization** | ADR-002, `SECURITY.md` §Data Protection & DLP | Presidio DLP, reversible tokenization, canary injection, OTel redaction allowlist | ✅ Implemented |
| **Change control** | ADR-006, ADR-008, `SECURITY.md` §Secure Development Lifecycle | Golden regression suite with 1.0 recall gate, CI/CD gates, semantic versioning, 6-phase roadmap | ✅ Implemented |
| **Incident response** | `SECURITY.md` §Incident Response | Escalation path (Tier 1/2/3), containment procedures, opt-in runtime detection (ADR-017) | ✅ Implemented |
| **Transparency & explainability** | ADR-005, ADR-007, `SECURITY.md` §Observability & Telemetry | Hash-chained audit logs, Command Control dashboard, OTel spans with redaction allowlist | ✅ Implemented |
| **Fail-closed design** | ADR-001, ADR-004, `SECURITY.md` §Fail-Closed by Default | If safety layer down, requests blocked, never forwarded unscanned | ✅ Implemented |
| **Vendor lock-in avoidance** | ADR-004, ADR-008, `SECURITY.md` §Deployment Security | OmniRoute model routing, local fallback, drop-in Docker Compose upgrades, multi-provider config | ✅ Implemented |

---

## 📋 Customer Security Questionnaires

### Common Questions & Answers

#### Q: Does the system enforce segregation of duties?
**A:** Yes. Bastion-Agent enforces four-eyes HITL approval for state-changing tools (`read_only=False`). The approver cannot be the initiator (`approver_id != initiator_id`), and operator roles are time-bound and require sponsorship. See ADR-003 and ADR-009.

#### Q: How are audit logs protected from tampering?
**A:** Audit logs are stored in an append-only PostgreSQL table with SHA-256 hash chaining. The `record_hash` is computed as `SHA256(id || timestamp || actor_id || event_type || payload_hash || previous_hash)`. A verification endpoint (`/api/audit/verify`) recomputes the hash chain for a given range. See ADR-005.

#### Q: How does the system prevent data leaks?
**A:** Bastion-Agent uses a two-stage DLP pipeline: Presidio for PII/secrets detection, reversible tokenization in Redis vault (AES-256-GCM, 30-min TTL), and canary tripwires in egress. All tool outputs are scanned for canary presence before return. See ADR-002 and `SECURITY.md` §Data Protection & DLP.

#### Q: How are tool permissions managed?
**A:** Tool permissions are managed via a versioned tool catalog (`docs/tools/v1.json`) with `@tool(required_role="operator")` decorators. State-changing tools require four-eyes approval. See ADR-003 and ADR-009.

#### Q: How does the system handle prompt injection?
**A:** Bastion-Agent uses canary token injection, XML fence isolation, and egress filtering to detect and block indirect prompt injection. The system is fail-closed by default: if the safety layer is down, requests are blocked. See ADR-002 and `SECURITY.md` §Prompt Injection & Egress Defense.

#### Q: How are secrets managed?
**A:** Secrets are managed via environment variables (`.env` file, never committed). Key rotation is quarterly for `LLAMA_API_KEY`, `OPENROUTER_API_KEY`, and `REDIS_PASSWORD`. In production, use HashiCorp Vault or Azure Key Vault. See `SECURITY.md` §Secrets Management.

#### Q: How does the system ensure data residency?
**A:** Bastion-Agent routes confidential prompts to a local `llama.cpp` instance (Qwen 2.5 7B on RTX 3060 Ti) via OmniRoute. General prompts route to cloud providers. See ADR-004.

#### Q: How are changes to the system controlled?
**A:** Changes are controlled via a golden regression suite (`tests/data/goldens.jsonl`) with DeepEval metrics. Any change to DLP rules or classifier must pass a 1.0 recall gate in CI before merge. See ADR-006.

#### Q: How does the system handle incident response?
**A:** Incident response follows a three-tier escalation path: Tier 1 (AI Platform Team), Tier 2 (Identity Team), Tier 3 (Security Operations). Containment includes kill switch tiers, quarantine of affected runs, and preservation of hash-chained audit logs. See `SECURITY.md` §Incident Response.

---

## 📋 SOC 2 Type II Controls Mapping

| SOC 2 Type II Control | Evidence Source | Bastion-Agent Implementation | Status |
|-----------------------|-----------------|-------------------------------|--------|
| **CC6.1: The entity implements logical access security measures to protect against unauthorized access** | ADR-003, ADR-009, `SECURITY.md` §Authentication & Authorization | Keycloak OIDC JWT validation, four-tier roles, tool catalog allow-list, source-side entitlement | ✅ Implemented |
| **CC6.2: The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes** | ADR-002, ADR-004, `SECURITY.md` §Data Protection & DLP | Presidio DLP, reversible tokenization, local fallback, fail-closed design | ✅ Implemented |
| **CC6.7: The entity implements logical segregation of duties for systems that have multiple users** | ADR-003, ADR-009, `SECURITY.md` §Kill Switch Tiers | Four-eyes HITL approval, `approver_id != initiator_id`, time-bound operator roles | ✅ Implemented |
| **CC7.2: The entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities** | ADR-006, ADR-016, `SECURITY.md` §Vulnerability Management | Golden regression suite, CI/CD gates, OSV audit of `uv.lock`, Trivy image scan and CycloneDX SBOM in the `supply-chain` job (`scripts/scan_images.sh`, artifacts under `artifacts/compliance/`) | ✅ Implemented |
| **CC7.4: The entity responds to identified security incidents by executing a defined incident response program** | ADR-017, `SECURITY.md` §Incident Response | Escalation path, containment procedures, opt-in Falco runtime detection, 72-hour regulator reporting | ✅ Implemented |
| **CC9.1: The entity communicates roles, responsibilities, and authorities for managing information security to internal and external users** | ADR-003, ADR-009, `SECURITY.md` §Authentication & Authorization | Four-tier roles, tool catalog allow-list, RBAC matrix, kill switch tiers | ✅ Implemented |
| **CC9.2: The entity communicates information about its information security policies and procedures to internal and external users** | `SECURITY.md`, `COMPLIANCE.md`, ADR-Index.md | Security policy, compliance matrix, ADR catalog | ✅ Implemented |

---

## 📋 FINMA Circular 2018/3 Mapping

| FINMA 2018/3 Clause | Evidence Source | Bastion-Agent Implementation | Status |
|----------------------|-----------------|-------------------------------|--------|
| **§4.2 Outsourcing** | ADR-001, ADR-004, `SECURITY.md` §Deployment Security | Single FastAPI ingress, deterministic DLP, local fallback, fail-closed design | ✅ Compliant |
| **§4.3 Segregation of Duties** | ADR-003, ADR-009, `SECURITY.md` §Kill Switch Tiers | Four-eyes HITL approval, `approver_id != initiator_id`, time-bound operator roles | ✅ Compliant |
| **§4.4 Monitoring** | ADR-007, ADR-017, `SECURITY.md` §Observability & Telemetry | Command Control dashboard, OTel spans, real-time approvals, opt-in Falco runtime alerts | ⚠️ Partial (opt-in) |
| **§4.5 Audit Trail** | ADR-005, `SECURITY.md` §Audit & Non-Repudiation | Hash-chained audit logs, verification endpoint, signed head witness under 7-year WORM retention (opt-in `compliance` profile) | ⚠️ Partial (witness opt-in; ledger partitioning/export is IDEA-004) |
| **§4.6 Change Management** | ADR-006, ADR-008, `SECURITY.md` §Secure Development Lifecycle | Golden regression suite, CI/CD gates, semantic versioning, 6-phase roadmap | ✅ Compliant |

---

## 📋 GDPR Mapping

| GDPR Article | Evidence Source | Bastion-Agent Implementation | Status |
|--------------|-----------------|-------------------------------|--------|
| **Art. 32 Security of Processing** | ADR-002, ADR-005, `SECURITY.md` §Data Protection & DLP | Presidio DLP, reversible tokenization, hash-chained audit logs, data minimization | ✅ Compliant |
| **Art. 30 Records of Processing** | ADR-005, `SECURITY.md` §Audit & Non-Repudiation | PostgreSQL `audit_logs` with `record_hash`, verification endpoint | ✅ Compliant |
| **Art. 44-49 Data Transfers** | ADR-004, `SECURITY.md` §Deployment Security | Local fallback to llama.cpp, cloud routing via OmniRoute, fail-closed design | ✅ Compliant |

---

## 📋 Swiss Banking Act Mapping

| Swiss Banking Act Article | Evidence Source | Bastion-Agent Implementation | Status |
|---------------------------|-----------------|-------------------------------|--------|
| **Art. 47 Banking Secrecy** | ADR-002, ADR-003, ADR-009, `SECURITY.md` §Data Protection & DLP | Presidio DLP, reversible tokenization, tool catalog allow-list, four-eyes approval | ✅ Compliant |
| **Art. 48 Data Protection** | ADR-005, `SECURITY.md` §Audit & Non-Repudiation | Hash-chained audit logs, verification endpoint, signed head witness under 7-year WORM retention (opt-in `compliance` profile) | ⚠️ Partial (witness opt-in; ledger partitioning/export is IDEA-004) |

---

## 📋 EU AI Act Mapping

| EU AI Act Article | Evidence Source | Bastion-Agent Implementation | Status |
|-------------------|-----------------|-------------------------------|--------|
| **Art. 10 Transparency** | ADR-001, ADR-009, `SECURITY.md` §Transparency & Explainability | Single FastAPI ingress, deterministic controls, hash-chained audit logs | ✅ Compliant |
| **Art. 15 Risk Management** | ADR-006, ADR-016, ADR-017, `SECURITY.md` §Vulnerability Management | Golden regression suite, CI/CD gates, OSV audit and Trivy image scan with a published SBOM, opt-in runtime detection | ✅ Compliant |
| **Annex III High-Risk AI Systems** | ADR-001, ADR-004, `SECURITY.md` §Fail-Closed by Default | Fail-closed design, deterministic controls, auditability | ✅ Compliant |

---

## 📋 Compliance Testing & Validation

### Automated Compliance Checks

```bash
# 1. Audit chain verification
uv run python scripts/verify_audit_chain.py --range 2026-11-01:2026-11-09

# 2. DLP recall check (golden dataset)
uv run pytest tests/test_dlp_evals.py -v

# 3. Tool catalog integrity
uv run python scripts/validate_tool_catalog.py

# 4. RBAC matrix validation
uv run python scripts/validate_rbac.py
```

### Manual Compliance Verification

| Requirement | Verification Method | Frequency |
|-------------|---------------------|-----------|
| **Non-repudiable audit trail** | Recompute hash chain for a given range | Quarterly |
| **Deterministic authorization** | Review tool catalog and RBAC matrix | Quarterly |
| **Least privilege access** | Review tool permissions and roles | Quarterly |
| **Segregation of duties** | Review approval workflow and operator roles | Quarterly |
| **Data minimization** | Review DLP rules and OTel redaction allowlist | Quarterly |
| **Change control** | Review golden regression suite and CI/CD gates | Quarterly |
| **Incident response** | Review incident response procedures and logs | Quarterly |

---

## 📋 Compliance Documentation

| Document | Purpose | Owner | Location |
|----------|---------|-------|----------|
| **SECURITY.md** | Security policy and controls | AI Platform Team | Bastion-Agent root |
| **COMPLIANCE.md** | Regulatory alignment and evidence | AI Platform Team | Bastion-Agent root |
| **ADR-001.md** | Core Ingress & Zero-Trust Gateway | AI Platform Team | docs/adr/ADR-001.md |
| **ADR-002.md** | Two-Stage DLP & Reversible Token Vault | AI Platform Team | docs/adr/ADR-002.md |
| **ADR-003.md** | Declarative RBAC & Four-Eyes HITL | AI Platform Team | docs/adr/ADR-003.md |
| **ADR-004.md** | OmniRoute Model Routing & Failover | AI Platform Team | docs/adr/ADR-004.md |
| **ADR-005.md** | Cryptographic Audit Trail & Hash Chaining | AI Platform Team | docs/adr/ADR-005.md |
| **ADR-006.md** | DeepEval Golden Dataset & Regression Gating | AI Platform Team | docs/adr/ADR-006.md |
| **ADR-007.md** | Command Control Dashboard & HTMX Integration | AI Platform Team | docs/adr/ADR-007.md |
| **ADR-008.md** | Evolution Roadmap & Version Policy | AI Platform Team | docs/adr/ADR-008.md |
| **ADR-009.md** | Four-Gate Tool Governance Model | AI Platform Team | docs/adr/ADR-009.md |
| **SWISS-FDE-ALIGNMENT.md** | Swiss FDE alignment guide | AI Platform Team | docs/SWISS-FDE-ALIGNMENT.md |

---

## 📋 Compliance Roadmap

| Phase | Milestone | Compliance Target | Status |
|-------|-----------|-------------------|--------|
| **v0.1** | MVP — core gateway, DLP, routing, audit, basic dashboard | FINMA 2018/3, GDPR Art. 32, SOC 2 Type II (Logging) | ✅ Complete |
| **v0.2** | Hardening — multi-model DLP, eval-driven routing, canary hardening | FINMA 2018/3, GDPR Art. 32, SOC 2 Type II (Change Control) | ✅ Complete |
| **v0.3** | Multi-tenancy — tenant isolation, Redis namespaces, multi-region routing | SOC 2 Type II (Access Controls), GDPR Art. 44-49 | Planned |
| **v0.4** | Adaptive policy — adaptive DLP, LLM-as-judge egress, dynamic RBAC | EU AI Act, SOC 2 Type II (Risk Management) | Planned |
| **v0.5** | Production readiness — PostgreSQL HA, Redis HA, backup/restore | SOC 2 Type II (Availability), FINMA 2018/3 (Outsourcing) | Planned |
| **v0.6** | Future-proofing — multi-provider OmniRoute, local model hot-swap | Vendor lock-in avoidance, SOC 2 Type II (Change Management) | Planned |

---

## 📋 Contact & Support

### Compliance Team
- **Slack**: `#ai-platform-compliance`
- **Email**: compliance@bastion-agent.ai
- **PGP**: [PGP Key ID] (published on company website)

### Reporting a Compliance Issue
1. **Email**: compliance@bastion-agent.ai (PGP-encrypted)
2. **Include**: Description, impact, evidence, suggested remediation
3. **Response**: Acknowledgment within 24 hours, remediation within 7 days (critical), 30 days (moderate)

---

## 📋 References

- [FINMA Circular 2018/3 – Outsourcing](https://www.finma.ch/en/~/media/finma/dokumente/dokumentencenter/myfinma/1aussenstellen/20180827_circ_18_03_e.pdf)
- [GDPR Art. 32 – Security of Processing](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679)
- [Swiss Banking Act (SR 954.1)](https://www.fedlex.admin.ch/eli/cc/1934/577_581_583/en)
- [SOC 2 Type II Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpaas-cs-homepage)
- [EU AI Act – High-Risk AI Systems](https://artificialintelligenceact.eu/)
- [Microsoft Enterprise Agent Security and Tool Governance](https://github.com/microsoft/agenticai-design-patterns)
- [Occludra AI Security Gateway](https://github.com/occludra/gateway)

---

## 📋 Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-11-09 | Initial release | AI Platform Team |

---

## 📋 License

Bastion-Agent is licensed under the **MIT License**. Compliance documentation is **Internal Use Only**.

---

**File saved:** `COMPLIANCE.md` in Bastion-Agent project root

**Purpose:** To be referenced in customer security questionnaires, compliance audits, and regulatory reviews.