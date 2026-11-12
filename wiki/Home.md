# Bastion-Agent Wiki

> **High-Assurance, Zero-Trust Enterprise AI Agent Harness & Control Plane**

## Overview

Bastion-Agent is an enterprise-grade agent runtime designed for high-security and regulated environments. It enforces deterministic Data Leak Prevention (DLP), semantic confidential prompt routing to local inference, four-eyes human-in-the-loop tool guards, OpenTelemetry observability, and continuous regression evaluations with DeepEval.

## Key Features

- **Two-Stage DLP Pipeline**: Microsoft Presidio entity detection with AES-256-GCM encrypted token vault
- **Confidentiality Routing**: Routes sensitive prompts to local llama.cpp, general queries to cloud providers
- **SSO & RBAC**: Keycloak OIDC integration with role-based tool visibility
- **Four-Eyes HITL Governance**: Human approval required for state-changing operations
- **Egress Canary Tripwires**: Detects and blocks prompt injection attacks
- **Tamper-Evident Audit Ledger**: SHA-256 hash-chained audit logging
- **Dual Observability**: OpenTelemetry exports to Langfuse, Arize, or Better Stack
- **Eval-Driven Gating**: DeepEval golden benchmarks with 100% recall requirement

## Table of Contents

- [Installation Guide](Installation)
- [Architecture](Architecture)
- [Security Controls](Security)
- [Swiss Compliance](Swiss-Compliance)
- [ADR Index](ADR-Index)
- [Development](Development)
- [Troubleshooting](Troubleshooting)

---
*This wiki is synchronized from the docs/ directory of the main repository.*
