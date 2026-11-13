### IDEA-005: Reject canary prefixes shorter than eight characters at startup

- status: done
- priority: P1
- phase: v0.2
- area: security
- tags: canary, egress, validation, config
- depends-on: -
- spec: ADR-012
- created: 2026-11-10
- updated: 2026-11-11
- source: review of CANARY_PREFIX handling

**Problem**

`CANARY_PREFIX` is read from the environment and used as the
match token for `inspect()`. An empty or one-character prefix either blocks every
response or matches arbitrary text, and nothing rejected it at startup.

**Outcome**

Settings refuse a prefix shorter than eight characters, the failure is
explicit at boot rather than at the first request, and tests pin the minimum.

**Acceptance**

- [x] Settings validation rejects prefixes shorter than 8 characters
- [x] Startup failure names the variable and the minimum length
- [x] A test covers empty, one-character and valid prefixes
- [x] `.env.example` documents the constraint

**Notes**

- The acceptance floor of 8 exposed a conflict: the shipped default `CANARY-` is 7 characters, so enforcing it as written would have made the default configuration unstartable. The default is now `BASTION-CANARY-` (15 characters); the alternative of lowering the floor to 7 was rejected because it leaves the shipped marker one character above the dangerous range. Recorded in ADR-012 decision 1.
- The floor is enforced twice: `Settings._validate_canary_prefix` rejects it at startup with `CANARY_PREFIX must be at least 8 characters; got N`, and `EgressSanitizer` applies the same check to an explicit `canary_prefix=` override so a test fixture or script cannot bypass the boot check. `canary_prefix=""` now raises instead of silently falling back to the configured default.
- Upgrade note: canaries already in Redis keep the old `CANARY-` format until their 30-minute TTL lapses, and the new pattern does not match them. Restarting a deployment with the new default therefore leaves a TTL-bounded window in which a pre-upgrade marker would not trip the gate; drain sessions or accept the window. Recorded in ADR-012 decision 1.
- Files changed: `settings.py` (constant, default, validator), `agent/egress/sanitizer.py` (floor and override handling), `.env.example`, `docker-compose.yml`, the five test modules that pin the prefix, `scripts/demo_egress.py`, and the ADR/README/SECURITY/THREAT_MODEL/DEMO/HANDOVER_SPEC references to the marker format.
- Verification: `ruff check .` clean, `ruff format --check .` clean, `mypy` clean on the gate targets, `pylint` 10.00/10, full `pytest` 609 passed / 2 skipped (the two `model_integration` probes, no `LLAMA_CPP_BASE_URL`), and `check_adrs.py`, `validate_tool_catalog.py --check`, `validate_rbac.py`, `recalculate_dread.py --check` all pass.
