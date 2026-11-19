### IDEA-087: Make the README quickstart commands use the Vault env files

- status: done
- priority: P1
- phase: v0.5
- area: docs
- tags: docs, compose, onboarding
- depends-on: -
- spec: ADR-021
- created: 2026-11-19
- updated: 2026-11-19
- source: operator report in session, reproduced against the main checkout on 2026-11-19

**Problem**

README quickstart step 4 tells a fresh operator to run `docker compose up -d`. Since ADR-021 decision 5 moved every credential into a gitignored `.env.vault`, which Compose does not load on its own, that command aborts during interpolation: `required variable POSTGRES_PASSWORD is missing a value: set POSTGRES_PASSWORD in .env`. The Makefile already layers `--env-file .env --env-file .env.vault` and adds the Vault overlay, so `make up` is the supported entry point; the README still documents the pre-migration command.

**Outcome**

README quickstart step 4 starts the stack with `make up` and states that a bare `docker compose up` fails because the secrets live in `.env.vault`; step 5's post-bootstrap gateway/worker restart uses the same entry point.

**Acceptance**

- [x] README step 4 uses `make up` and explains that `.env.vault` is why a bare `docker compose up` fails
- [x] README step 5 no longer calls `docker compose up` directly for the gateway and worker restart
- [x] `uv run python scripts/check_adrs.py` and `scripts/gate.sh` pass with no other README section changed

**Notes**

- Reproduced on 2026-11-19 in the main checkout; `make up` exited 0 and all ten containers reached up/healthy, gateway and llama.cpp `/health` both `{"status":"ok"}`.
- The other raw `docker compose` commands elsewhere in the README (profiles, demo, OTel recreate) have the same flag requirement; this item fixes the quickstart path the report names, and the step-4 explanation covers the rest without rewriting every snippet.
- Verification (2026-11-19): `make up` in the main checkout exited 0 with all ten containers up/healthy; `scripts/check_adrs.py` reported 27 consistent ADRs and `scripts/gate.sh` reported 14/14 passed. The first gate run failed `infra` and `test_audit_witness` because `scripts/dev/worktree.sh start` links only `.env`, not the gitignored `.env.vault`; symlinking it into the worktree fixed both. That setup gap is not part of this README change and should be captured on its own.
