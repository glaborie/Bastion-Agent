### IDEA-006: Add a deterministic egress canary demo

- status: done
- priority: P3
- phase: v0.2
- area: docs
- tags: demo, canary, egress
- depends-on: -
- spec: ADR-012
- created: 2026-11-09
- updated: 2026-11-10
- source: review of DEMO.md, Act 6

**Problem**

Asking a model to leak its system marker is not a demo: it may refuse,
comply or paraphrase, so the evidence changed every run.

**Outcome**

`scripts/demo_egress.py` runs the real sanitizer, real Redis keys and
real vault against the exact completion text the egress stage would inspect.

**Acceptance**

- [x] One `CANARY-<uuid4>` per session, stable across turns
- [x] Leak blocked with empty delivered text and the session quarantined
- [x] Next turn rejected before inference
- [x] Vault marker restored only for its own session
- [x] Tool payload cannot close `</untrusted_content>`
- [x] Demo passes on the host and inside the gateway container
