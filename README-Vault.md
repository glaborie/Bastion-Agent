# Vault secrets management - Bastion-Agent

HashiCorp **Vault** is the secrets store for this stack. It replaces the
hand-typed `.env` file with a single encrypted source of truth, and it runs
as a container inside the existing Docker Compose stack.

## Why Vault

- **Free and self-hosted** — Apache 2.0, no cloud dependency, no vendor lock-in
- **Container-native** — official `hashicorp/vault:1.17.0` image, runs on the
  existing Compose network
- **Security-expert-approved** — used by Mozilla, Shopify, Coinbase; the
  Swiss-market reference architecture
- **Compliance-ready** — audit logging, dynamic secrets, access control
  policies, zero-trust design
- **No plaintext secrets in git** — generated material is gitignored

## Architecture

```
docker-compose.yml          (existing stack, untouched)
docker-compose.vault.yml    (additive overlay only)

services added:
  vault            → Vault server (Raft integrated storage, self-signed TLS)
  vault-bootstrap  → one-shot init + unseal + policy write + seed

ports:
  127.0.0.1:8200   → API / UI
  8201             → cluster listener (container-internal, not published)

Secrets flow:
  Every credential (infra and application) is seeded in Vault; the
  externally-issued model/observability keys are imported once.
  `make vault-export` materialises all of them, plus the host
  DATABASE_URL/REDIS_URL, into gitignored .env.vault.
  settings.py loads .env.vault as a second dotenv source after .env, so host
  tooling sees the same values the containers do.
```

No Vault CLI is needed on the host: every Makefile target runs `vault` inside
the running container. Only Docker and Docker Compose are required.

## Quick start

```bash
# 1. Generate the TLS cert, build, start Vault, init/unseal and seed it
make vault-up

# 2. Copy the externally-issued secrets (OpenRouter, llama.cpp, Langfuse,
#    Arize, Opik, Hugging Face) from .env into Vault once
make vault-import

# 3. Materialise every credential into a gitignored .env.vault
make vault-export

# 4. Delete every line `vault-export` wrote from `.env` (the 25 keys);
#    `make vault-check` and the plaintext gate name any that remain
make vault-check

# 5. Start the full stack (layers .env.vault over .env)
make up

# 6. On a fresh OmniRoute volume, register the gateway key in Vault and re-export
uv run python scripts/omniroute_bootstrap.py --write-vault
make vault-export
docker compose up -d --no-deps gateway worker   # only if a key was written
```

That is the only start path. `make up` layers `.env.vault` over `.env` (a later
`--env-file` wins) and the app services load it as a second `env_file`, so the
credentials Vault materialised are the ones the stack runs with while every
other setting still comes from `.env`. `settings.py` loads the same pair, so
`uv run pytest`, Alembic and the scripts see the Vault values too. Without
`.env.vault` the render is exactly the hand-typed-`.env` one, so a fresh clone
still starts.

Once the lines are deleted, `scripts/check_env_vault.py --check-plaintext` (a
gate step) fails, naming only the key, if a secret is typed back into `.env`.
The seven infra lines must go too: leaving a development copy in `.env` shadows
`.env.vault` for host tooling, because a process environment entry wins over a
dotenv file (DeepEval's pytest plugin exports `.env` this way). `.env.example`
keeps the development defaults so a clone without Vault remains startable.

If `.env.vault` is incomplete, or Vault has been rotated since it was written,
`make vault-check` stops you before the stack starts:

```bash
make vault-check   # keys present, and every value still matches Vault
```

Every Vault-sourced key below is materialised; `.env` keeps a development copy
of the seven infra keys, and is overridden whenever `.env.vault` exists. The
sixteen application-secret lines are deleted from `.env` once the stack is on
Vault (step 4 above), because the plaintext gate treats them as a leak.

## TLS certificate

`vault/certs/vault.crt` and `vault.key` are **not committed**: they are
generated per host by `make vault-up` (a `vault/certs/vault.crt` prerequisite
target), valid 825 days, with `DNS:vault`, `DNS:localhost` and `IP:127.0.0.1`
as SANs. To regenerate:

```bash
rm vault/certs/vault.crt && make vault-up
```

The private key is `root:vault 0640` inside the image, so the `vault` user can
read it but it is never world-readable.

## Unseal key and dev token

- `vault operator init` runs once, inside the bootstrap container, with one
  share. The unseal key is written to `/vault/data/unseal.key` **in the
  `vault-data` volume** (dev only). Vault re-seals on every start, so after a
  container or host restart run `make vault-up` again: it unseals with that key
  and does not re-seed.
- Dev secrets are seeded only when `bastion/db/postgres` does not exist yet, so
  unsealing never rotates creds a running stack already uses. `vault-export`
  fails loudly until the store is unsealed.
- The random root token printed by `init` is not used. Bootstrap instead
  creates a fixed dev token, `dev-root-token-bastion`, with the `root` policy.
  That is the token in `docker-compose.vault.yml` and in the Makefile.
- If the unseal key is lost (volume deleted, key file removed), the node cannot
  be unsealed. Reset the dev store and re-seed:

  ```bash
  docker compose -f docker-compose.yml -f docker-compose.vault.yml down vault vault-bootstrap
  docker volume rm bastion-agent_vault-data
  make vault-up
  ```

  All dev secrets are regenerated, so re-run `make vault-export` afterwards.

## Mount and what gets stored where

KV v2 is mounted at **`bastion/`** (physical paths `bastion/data/...`), which is
what `vault/policies/*.hcl` grant read access to.

| Secret | Vault path | Consumed by | How |
|--------|-----------|-------------|-----|
| POSTGRES_PASSWORD | bastion/db/postgres | db | vault-export → .env.vault |
| POSTGRES_APP_USER / POSTGRES_APP_PASSWORD | bastion/db/postgres | gateway, worker, migrate | vault-export → .env.vault |
| REDIS_PASSWORD | bastion/db/redis | redis, gateway, worker | vault-export → .env.vault |
| KEYCLOAK_ADMIN_PASSWORD | bastion/db/keycloak | keycloak | vault-export → .env.vault |
| KEYCLOAK_CLIENT_SECRET | bastion/db/keycloak | gateway | vault-export → .env.vault |
| MINIO_ROOT_PASSWORD | bastion/db/minio | minio, minio-init | vault-export → .env.vault |
| AUDIT_WITNESS_ACCESS_KEY / AUDIT_WITNESS_SECRET_KEY | bastion/db/minio | minio-init, witness scripts | vault-export → .env.vault |
| PGADMIN_DEFAULT_PASSWORD | bastion/db/pgadmin | pgadmin | vault-export → .env.vault |
| OMNIROUTE_ADMIN_PASSWORD | bastion/db/omniroute | omniroute | vault-export → .env.vault |
| OMNIROUTE_API_KEY | bastion/app/oauth | gateway, worker | vault-export → .env.vault |
| OPENROUTER_API_KEY, LLAMA_API_KEY | bastion/app/oauth | omniroute, llama-cpp | vault-import → vault-export |
| VAULT_MASTER_KEY, PAYLOAD_ESCROW_MASTER_KEY | bastion/app/dlp | gateway, worker | vault-export → .env.vault |
| APPROVAL_HMAC_SECRET, JOB_SIGNING_SECRET | bastion/app/jwt | gateway, worker | vault-export → .env.vault |
| AUDIT_WITNESS_HMAC_SECRET | bastion/app/audit | witness scripts | vault-export → .env.vault |
| HF_TOKEN | bastion/app/models | models-init | vault-import → vault-export |
| LANGFUSE_SECRET_KEY, ARIZE_API_KEY, OPIK_API_KEY | bastion/app/observability | otel-collector | vault-import → vault-export |

`vault-export` also writes the host `DATABASE_URL` and `REDIS_URL` into
`.env.vault`, composed from the Vault Postgres/Redis password plus the
non-secret `POSTGRES_USER`, `POSTGRES_DB`, `POSTGRES_PORT` and `REDIS_PORT` in
`.env`. The app containers never receive those localhost URLs: the compose
anchor keeps the container-internal `db:5432` and `redis:6379` values.

`KEYCLOAK_CLIENT_SECRET` is the one seeded value that is not generated: the
realm import pins it in `config/keycloak/realm-export.json`, and the gateway
exchanges the authorization code with the env value, so a random value would
break the dashboard login. It stays the committed dev value;
`_reject_dev_secrets` still refuses it outside local development. Rotating it
means changing the realm file, the bootstrap constant and Vault together.


## Makefile targets

| Target | What it does |
|--------|-------------|
| `make vault-up` | Generate the cert if missing, build, start Vault, bootstrap and seed |
| `make vault-down` | Stop Vault containers (the data volume persists) |
| `make vault-shell` | Open an interactive shell in the Vault image |
| `make vault-export` | Materialise every Vault credential into gitignored `.env.vault` (mode 600) |
| `make vault-import` | Copy the externally-issued secrets from `.env` into Vault once |
| `make vault-check` | Fail if `.env.vault` is incomplete or has drifted from Vault |
| `make vault-list` | List secret paths under `bastion/` (no values) |
| `make vault-rotate SECRET=db/postgres` | Patch one field (path default, override with `FIELD=...`) |

`vault-rotate` patches the field `vault-export` reads (the path defaults are in
the Makefile; pass `FIELD=` for `app/jwt` or the second password on a path). A
database or Redis password rotation only changes the Vault value: update the
running role or `requirepass` as well, or the next start still authenticates
with the old one.

`vault-export` fails loudly and deletes `.env.vault` if a required value comes
back empty, so a sealed or unseeded Vault cannot leave you with a
plausible-looking file full of blanks.

## Environment variables

The containers do not talk to Vault: `make up` gives them the materialised
`.env.vault` as a second `env_file`. Vault itself and the Makefile targets need:

```
VAULT_ADDR=https://vault:8200
VAULT_TOKEN=***
```

The dev token (`dev-root-token-bastion`) is created by the bootstrap for local
development only — rotate it before any staging or production use. The `vault`
container also sets `VAULT_SKIP_VERIFY`, because the dev certificate is
self-signed.

`.env.vault` is plaintext at mode 600 and readable by every process running as
the developer, exactly like `.env` was. It removes the hand-typed duplicate and
the drift between Vault and `.env`; it does not reduce at-rest or `docker
inspect` exposure. `IDEA-020` is the production successor (runtime reads,
AppRole identities, no secret in the environment).

## Production path

1. Replace the dev token with AppRole or Kubernetes auth.
2. Use a real TLS certificate instead of the self-signed one.
3. Add raft nodes for high availability, keeping `cluster_addr` on port 8201
   (see `vault/config.hcl` comments).
4. Inject unseal keys via a secrets manager or HSM (never write them into the
   data volume, as `/vault/data/unseal.key` does here for dev).
5. Enable audit logging to a write-only destination.

## Git hygiene

`.env.vault` and `vault/certs/` are gitignored. The committed `vault/`
directory contains only config, policies, the Dockerfile and the bootstrap
script — no secrets, no private keys.
