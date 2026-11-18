### IDEA-076: Move the remaining application secrets out of .env into the Vault dev overlay

- status: ready
- priority: P2
- phase: v0.3
- area: infra
- tags: secrets, vault, docker, dev-experience, config, rotation
- depends-on: -
- spec: ADR-021
- created: 2026-11-18
- updated: 2026-11-18
- source: session 2026-11-18 ("I just want to get rid of secrets stored in the .env file")

**Problem**

`make vault-export` already materialises seven infra credentials from the Vault dev
overlay (`ADR-021`) into a gitignored `.env.vault`, and `COMPOSE_ENV` layers that file
after `.env`, so those seven can be rotated without hand-editing anything. Nothing else
is covered. `.env` still carries, as hand-typed literals, `VAULT_MASTER_KEY`,
`APPROVAL_HMAC_SECRET`, `JOB_SIGNING_SECRET`, `PAYLOAD_ESCROW_MASTER_KEY`,
`AUDIT_WITNESS_ACCESS_KEY`, `AUDIT_WITNESS_SECRET_KEY`, `AUDIT_WITNESS_HMAC_SECRET`,
`OMNIROUTE_API_KEY`, `OMNIROUTE_ADMIN_PASSWORD`, `PGADMIN_DEFAULT_PASSWORD`, `HF_TOKEN`,
`OPENROUTER_API_KEY`, `LLAMA_API_KEY`, `LANGFUSE_SECRET_KEY`, `ARIZE_API_KEY` and
`OPIK_API_KEY`, and the Postgres and Redis passwords twice more inside the host-side
`DATABASE_URL` (`settings.py:53`) and `REDIS_URL` (`settings.py:59`). Those URLs are the
ones a host `uv run pytest`, an Alembic run or a script uses, so they cannot simply be
deleted. There is also a claim the tree does not keep: the header `make vault-export`
writes into `.env.vault` says application secrets "are read from Vault at runtime and
never appear here".

Two consequences. The source of truth is split: `make vault-rotate` moves a Vault value
that `.env` still carries a stale copy of, and only `.env.vault` is checked for drift.
And the one file `SECURITY.md` tells an operator to protect is the file every one of
these values is typed into. This item is dev provisioning only: `settings.py:41` still
reads `env_file=".env"`, so host tooling never sees `.env.vault`, and the runtime read
path, AppRole identities and `docker inspect` exposure stay with `IDEA-020`.

**Outcome**

Every secret is generated or imported into Vault once, `.env.vault` is the only place a
secret literal is written on the host, and `.env` holds configuration and nothing else.
`settings.py` loads `.env.vault` as a second dotenv source after `.env`, so host tooling
sees the same values the containers do, and the host `DATABASE_URL`/`REDIS_URL` are
composed in `vault-export` from the Vault password plus the non-secret user, database and
port already in `.env` instead of embedding a copy. `make vault-check` names a missing or
diverged key without printing a value. The fresh-clone path is unchanged: with no
`.env.vault`, `cp .env.example .env` renders exactly as today and CI is unaffected.

**Acceptance**

- [ ] A committed check (`scripts/check_env_vault.py` extended, or `scripts/check_env_plaintext.py`) fails, naming only the key, when any of the sixteen secret keys above has a non-empty literal in `.env` or a password inside the host `DATABASE_URL`/`REDIS_URL`, and never prints a value; it passes against `.env.example` (the dev defaults stay) and runs in `scripts/gate.sh`, so a secret typed back into `.env` is a red check and not a review comment
- [ ] On a clean `vault-data` volume, `make vault-up` seeds every listed key: random for the five `_reject_dev_secrets` values (`settings.py:23-27`), the escrow key, the witness pair, `OMNIROUTE_API_KEY`, `OMNIROUTE_ADMIN_PASSWORD` and `PGADMIN_DEFAULT_PASSWORD`; a documented one-shot import copies the externally-issued `OPENROUTER_API_KEY`, `LLAMA_API_KEY`, `LANGFUSE_SECRET_KEY`, `ARIZE_API_KEY`, `OPIK_API_KEY` and `HF_TOKEN` from the current `.env` once, writes an empty value when unset, and prints no value; the existing "seed only on first run" guard for `bastion/db/*` still holds, proven by a second `make vault-up` leaving a running stack's values unchanged
- [ ] `make vault-export` writes all sixteen keys plus the host `DATABASE_URL` and `REDIS_URL`, the two URLs composed from the Vault password and the non-secret `POSTGRES_USER`/`POSTGRES_DB`/`POSTGRES_PORT` in `.env`; `make vault-check` exits non-zero naming the key when `.env.vault` is missing one or differs from the live `bastion/` entry, and prints no value in either failure
- [ ] `settings.py`'s `env_file` is the ordered pair `(".env", ".env.vault")` (`.env.vault` optional), proven by a test that a key present only in `.env.vault` is visible on `Settings` while the `.env` copy no longer wins; with no `.env.vault` the settings object is identical to today's, so `uv run pytest -q` and CI stay green
- [ ] Precedence is re-proven for the new keys: with sentinels in a temp `.env.vault`, `docker compose --env-file .env --env-file .env.vault config` shows each sentinel and the `.env` dev value nowhere, and the `gateway`/`worker` containers still receive the container-internal `DATABASE_URL`/`REDIS_URL` from the `x-app-environment` anchor (`docker-compose.yml:28,32`) rather than the host-localhost pair
- [ ] End to end on a clean volume: `cp .env.example .env`, `make vault-up`, `make vault-export`, delete the sixteen lines from `.env`, `make up`, `/health` ready and one chat turn succeeds; a rotation (`make vault-rotate SECRET=db/postgres`) followed by `vault-export` and a restart starts the stack on the new value with no `.env` edit
- [ ] `README-Vault.md`, the `.env.example` header and `ADR-021` decision 5 describe the full key set, the host-URL composition and the `settings.py` dotenv pair; `ADR-021`'s `Last modified` is bumped and its Consequences state that `.env.vault` is still plaintext at mode 600; the "read from Vault at runtime" sentence in the `vault-export` header is made true for this item's scope or removed, and `scripts/gate.sh` is green

**Notes**

- Dedupe: grepped `backlog/items/`, `BACKLOG.md`, `docs/adr/` for `env.vault`, `vault-export`, `app secrets`, `settings` and `dotenv`. `IDEA-056` (done) built the `.env.vault` consumption path for five infra keys and this extends the same mechanism to the keys it left out; `IDEA-057` (done) is the ADR record. `IDEA-020` is the production successor — runtime KV reads, AppRole, fail-closed boot — and this item deliberately keeps secrets in the process environment, so it must not absorb that design.
- Boundary against `IDEA-020`: this item does **not** reduce at-rest or environment exposure. `.env.vault` is still plaintext at mode 600 and every value still reaches the containers through `env_file`, so `docker inspect` still prints them. What it removes is the hand-typed duplicate and the silent drift between Vault, `.env` and the running stack. That limit belongs in the ADR amendment, not in a footnote.
- The URL literals are in scope on purpose. Moving the standalone keys while leaving a Postgres password inside `DATABASE_URL` would meet the letter of the request and none of the point, and the existing check already treats the URL as a secret-bearing value.
- Classification: `P2`/`v0.3`/`infra`, matching `IDEA-056` and `IDEA-057`; the overlay is v0.3 work and `ADR-008` puts the production mechanism in v0.5. Not `P1`: nothing is broken today and the stack starts from `.env` exactly as before.
- Honest limit: a lost `.env.vault` and a stopped Vault are recoverable with `make vault-export`; a lost `vault-data` volume rotates every credential and needs a stack rebuild, which is already `ADR-021`'s documented consequence.
- `spec: ADR-021` is the amendment target: extending decision 5 and its Consequences is the record this change needs, and no new ADR is warranted because the mechanism, the auth model and the limits are unchanged.
- Scope: intake only. No `settings.py`, `vault/bootstrap.py`, Makefile, compose, script, `.env` or document edit is part of this capture.
