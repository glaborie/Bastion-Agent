# ADR Index

A curated list of Architectural Decision Records for Bastion-Agent. Each ADR is
a file in this directory; this page is the index and the process guide.

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
| 018 | Signed Job Envelopes for Worker Identity | Accepted |

---

## How to Add a New ADR

1. Take the next free number (see the table above) and copy an existing ADR's
   structure into `docs/adr/ADR-XXX.md`.
2. Keep the required sections: title line `# ADR-XXX: <Title>`, the
   `**Status:**` / `**Date:**` / `**Last modified:**` block, `## Context`
   (at least two paragraphs), a numbered `## Decision`, and
   `## Consequences` with `**Pros**` and `**Cons**` bullets.
3. Use one of the statuses `Proposed`, `Accepted`, `Superseded`, `Deprecated`,
   with ISO dates (`YYYY-MM-DD`).
4. Add the row to the table above, in numeric order.
5. Run `uv run python scripts/check_adrs.py` — it validates structure, dates,
   index coverage and machine-local paths.
6. Commit the ADR and the index together.

## How to Remove or Supersede an ADR

- **Supersede** (preferred): add a new ADR, set the old file's `Status` to
  `Superseded`, and reference the replacement in both files.
- **Remove**: delete `docs/adr/ADR-XXX.md` and remove its entire table row.
- Never leave a blank pipe-delimited row or an index entry without a file.

## Conventions

- Decisions describe what the system **does**, not aspirations. When an
  implementation diverges, update the ADR in the same change (and bump
  `Last modified`).
- No absolute machine-local paths, hostnames or credentials in an ADR.
- ADRs are immutable history once superseded: do not rewrite a superseded ADR.
