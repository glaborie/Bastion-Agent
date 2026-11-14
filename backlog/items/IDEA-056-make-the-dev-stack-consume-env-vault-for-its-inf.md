### IDEA-056: Make the dev stack consume .env.vault for its infra credentials

- status: inbox
- priority: P2
- phase: v0.3
- area: infra
- tags: docker, secrets, compose, dev-experience
- depends-on: -
- spec: -
- created: 2026-11-14
- updated: 2026-11-14
- source: 2026-11-14 review of the vault overlay (`vault-secrets-overlay`, PR #42) and its `make vault-export` output against a live Vault

**Problem**

`make vault-export` materialises five infra credentials into a mode-600 `.env.vault` (Makefile:42-59 on the `vault-secrets-overlay` branch), but nothing consumes that file: `COMPOSE` is `docker compose -f docker-compose.yml -f docker-compose.vault.yml` (Makefile:8) with no `--env-file`, so `make up` interpolates the hand-typed `.env`, and the compose error text still says "set POSTGRES_PASSWORD in .env" (`docker-compose.yml:23`, `:27`, `:32`, `:209`, `:264`, `:276`, `:282`, `:325`). README-Vault.md:55-60 documents the manual `docker compose --env-file .env.vault ...` invocation and states plainly that `make up` does not load the file, so the materialised file reaches nothing. The naive fix is not one flag: `--env-file` replaces the project `.env` for interpolation, and `.env.vault` holds 5 of the file's 140 `${...}` references, so `--env-file .env.vault` alone fails closed on the five other required `:?` keys (`VAULT_MASTER_KEY` at `docker-compose.yml:55`, `APPROVAL_HMAC_SECRET`, `OMNIROUTE_ADMIN_PASSWORD`, `PGADMIN_DEFAULT_EMAIL`, `PGADMIN_DEFAULT_PASSWORD`) and silently defaults the rest — while `MINIO_ROOT_PASSWORD` from Vault never takes effect at all, because compose falls back to `dev-only-minio-root-password` (`:524`, `:557`). The result is two sources of truth for the same credentials: `make vault-rotate` + `make vault-export` changes Vault but not the running stack, and nothing compares the two, so drift stays silent until a restart picks up a password Vault no longer holds.

**Outcome**

One documented start path renders the stack from `.env.vault` for the five infra credentials and from `.env` for everything else, so nobody has to remember a second `docker compose` invocation. Precedence is a proven property of that path: the rendered `docker compose config` carries the `.env.vault` value for each of the five and the `.env` value nowhere, and the other required keys still resolve. `make vault-check` compares `.env.vault` against the keys `docker-compose.yml` requires and against Vault, failing with the key name and never the value on a missing or diverging entry, so rotation without export becomes a red check instead of silent drift. With no `.env.vault`, `make up` either behaves exactly as today or stops with one actionable message before creating anything, never a half-started stack. README-Vault.md and `.env.example` describe that single path and mark the five as Vault-materialised.

**Acceptance**

- [ ] Precedence and completeness are proven, not assumed: with sentinel values written into a temp copy of `.env.vault`, the rendered output of the chosen mechanism (for example repeatable `--env-file`, `.env` first and `.env.vault` second) shows each sentinel in `DATABASE_URL`, `REDIS_URL`, the redis command and healthcheck, the Keycloak admin password and `MINIO_ROOT_PASSWORD` (`docker-compose.yml:23,27,264,276,282,325,524`), shows the `.env` value for those keys nowhere, and still resolves `VAULT_MASTER_KEY`, `APPROVAL_HMAC_SECRET`, `OMNIROUTE_ADMIN_PASSWORD` and the pgAdmin pair from `.env`; a committed `scripts/check_env_vault.py --render` (or pytest equivalent) asserts all three and fails when the `.env.vault` input is dropped
- [ ] A committed check fails, naming only the key, when a required key is missing from `.env.vault` (this mode runs in CI, which has no Vault) and when a `.env.vault` value differs from the corresponding `bastion/db/*` entry in a live Vault (`make vault-check`, requires Vault); a test mutates both cases against temp copies, asserts a non-zero exit, and greps the output for a sentinel secret to prove no value is printed
- [ ] With `.env.vault` absent, `make up` takes the implemented branch and that branch is proven: either the rendered config is identical to today's `.env`-only render, or the target prints one actionable line and exits before any container exists (`docker compose ps -q` empty); a test exercises the target in a copy of the tree and asserts the chosen branch, so a partially created stack fails the item
- [ ] README-Vault.md (quick start 42-60, target table 119-132) and `.env.example` (header 4-5) describe the single documented path: no hand-typed `.env` instruction for the five, no second manual `--env-file` invocation, the five marked as Vault-materialised, and the minimum Compose version stated if repeatable `--env-file` is used; `grep -n "does not load" README-Vault.md` returns nothing

**Notes**

- Dedupe: grepped `backlog/items/`, `BACKLOG.md` and `docs/adr/` for `env.vault`, `env-file`, `vault-export`, `compose` and `secrets`. Nothing covers it. `IDEA-019:93` mentions `--no-env-file` only for reproducible image-inventory scanning, and `ADR-016:17` / `ADR-011:189` describe Compose env-file precedence for the scanner and a GPU run example, not this. `IDEA-020` is the runtime OpenBao read path (`P2`/`v0.5`/`security`) and this item is start-time dev provisioning; the explicit boundary is that no API or settings read moves here, and this item must not grow into that design.
- Adjacent draft, not a duplicate: `adr-vault-dev-overlay` records the overlay itself in an ADR and reconciles SECURITY/COMPLIANCE/THREAT_MODEL. This item is the Makefile/compose consumption gap; the two meet only in README-Vault.md, and the ADR item should not absorb this acceptance or vice versa.
- Prerequisite: the overlay (Makefile, `docker-compose.vault.yml`, README-Vault.md, `vault/`) exists only on unmerged branch `vault-secrets-overlay` (PR #42), so this item is unbuildable before that lands. `depends-on: -` is literal: no backlog item exists for the overlay yet; if one is captured, this item should depend on it. If PR #42 is closed unmerged, this item is moot.
- Classification: `P2`/`v0.3`/`infra` per triage. It is a dev-experience defect in the overlay's start path, not the ADR-008 v0.5 secrets scope, and not `P0` because the stack still starts from `.env` exactly as before.
- Honest limit: `.env.vault` stays plaintext at mode 600 and readable by the developer's processes. This removes the duplicate hand-typed copy and the silent drift, not the at-rest exposure `IDEA-020` addresses; `.gitignore:3` (`.env.*` with `!.env.example`) already covers the file, so no gitignore change is needed.
- Scope: intake only. No Makefile, compose, script or document edit is part of this capture.
