# ADR Index

A curated list of Architectural Decision Records for Bastion-Agent.

## Decision Status

| ADR | Title | Status |
|-----|-------|--------|
| 001 | Core Ingress & Zero-Trust Gateway | Accepted |
| 002 | Two-Stage DLP & Reversible Token Vault | Accepted |
| 003 | Declarative RBAC & Four-Eyes HITL | Accepted |
| 004 | OmniRoute Model Routing & Failover | Accepted |
| 005 | Cryptographic Audit Trail & Hash Chaining | Accepted |
| 006 | DeepEval Golden Dataset & Regression Gating | Accepted |
| 007 | Command Control Dashboard & HTMX Integration | Accepted |
| 008 | Evolution Roadmap & Version Policy | Accepted |
| 009 | Four-Gate Tool Governance Model | Accepted |
| 010 | Guarded Tool Execution & Resume State Machine | Accepted |
| 011 | ONNX Semantic Sensitivity Classifier | Accepted |
| 012 | Egress Canary Tripwires, Untrusted-Content Fencing & Chat Lifecycle | Accepted |
| 013 | Per-Principal Rate Limiting | Accepted |
| 014 | Observability & Trace Privacy | Accepted |
| 015 | Tenant Isolation for Keys, Rows and Queries | Accepted |
| 016 | Container Image Scanning & SBOM Publication | Accepted |
| 017 | Runtime Detection with Falco | Accepted |

## How to Add a New ADR

1. Take the next free number and create `ADR-XXX.md`
2. Keep required sections: title, status, date, context, decision, consequences
3. Use statuses: `Proposed`, `Accepted`, `Superseded`, `Deprecated`
4. Add to this index table
5. Run validation: `uv run python scripts/check_adrs.py`

---
*This wiki page is a simplified view. See docs/adr/ADR-Index.md for full details.*
