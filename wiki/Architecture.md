# Architecture

## Overview

Bastion-Agent is an enterprise-grade agent harness that serves as a hardened policy enforcement point for agent operations in regulated environments.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Client / Caller                             │
└──────────────────────┬──────────────────────────────────────────┘
                       │ Bearer JWT (RS256)
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│           FastAPI Gateway & Command Control                   │
│  • OIDC JWT Validation & Declarative RBAC                     │
│  • Presidio Deterministic DLP Engine                          │
│  • Reversible In-Memory Token Vault (Redis)                   │
│  • ONNX Sensitivity Sequence Classifier                     │
│  • Canary Token Injection & Egress Scrubbing                  │
│  • Lightweight HTMX Command Control Center                    │
└─────────────┬─────────────────────┬───────────────────────────┘
            │                     │
    [Sync Audit Entry]    [Async Task]
            │                     │
            ▼                     ▼
┌─────────────────────┐   ┌───────────────────────────────────┐
│   PostgreSQL 16     │   │        Redis 7                    │
│  • Audit Chain     │   │  • ARQ Task Queue                 │
│  • Approvals      │   │  • AES Token Vault                │
└──────────┬──────────┘   └─────────────┬─────────────────────┘
           │                            │
           ▼                            ▼
┌─────────────────────┐   ┌──────────────────────────────────┐
│   ARQ Agent Worker  │   │   OmniRoute Gateway              │
│  • Tool Execution   │   │  • Cloud: OpenRouter              │
│  • HITL Suspension  │   │  • Local: llama.cpp server        │
└──────────┬──────────┘   └──────────┬───────────────────┬───┘
           │                         │                   │
           │           ┌─────────────▼───┐     ┌─────────▼──────────┐
           │           │ OpenRouter API  │     │ llama.cpp (Qwen    │
           │           └───────────────────┘     │ 2.5 7B Q4_K_M)   │
           │                                     └──────────────────┘
           │
┌──────────▼──────────┐
│ Tamper-Evident Audit  │
│   Ledger (SHA-256)    │
└───────────────────────┘
```

## Key Architectural Decisions

| ADR | Decision |
|-----|----------|
| [ADR-001](ADR-Index) | Core Ingress & Zero-Trust Gateway |
| [ADR-002](ADR-Index) | Two-Stage DLP & Reversible Token Vault |
| [ADR-003](ADR-Index) | Declarative RBAC & Four-Eyes HITL |
| [ADR-004](ADR-Index) | OmniRoute Model Routing & Failover |
| [ADR-005](ADR-Index) | Cryptographic Audit Trail & Hash Chaining |
| [ADR-006](ADR-Index) | DeepEval Golden Dataset & Regression Gating |
| [ADR-007](ADR-Index) | Command Control Dashboard & HTMX Integration |
| [ADR-008](ADR-Index) | Evolution Roadmap & Version Policy |

---
*This page is synchronized from the [`wiki/`](https://github.com/glaborie/Bastion-Agent/tree/master/wiki) directory of the main repository.*
