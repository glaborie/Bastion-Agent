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
  Infra creds (postgres, redis, keycloak admin, minio root)
    materialised on demand into gitignored .env.vault by `make vault-export`
  App secrets (JWT signing, HMAC, OAuth client secret, API keys)
    seeded in Vault; the runtime read path is not wired into the app yet
```

No Vault CLI is needed on the host: every Makefile target runs `vault` inside
the running container. Only Docker and Docker Compose are required.

## Quick start

```bash
# 1. Generate the TLS cert, build, start Vault, init/unseal and seed it
make vault-up

# 2. Materialise infra creds into a gitignored .env.vault
make vault-export

# 3. Start the full stack
make up
```

`make up` does not load `.env.vault` by itself. To feed the materialised creds
to Compose, pass the file explicitly:

```bash
docker compose --env-file .env.vault -f docker-compose.yml -f docker-compose.vault.yml up -d
```

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
| REDIS_PASSWORD | bastion/db/redis | redis | vault-export → .env.vault |
| KEYCLOAK_ADMIN_PASSWORD | bastion/db/keycloak | keycloak | vault-export → .env.vault |
| KEYCLOAK_CLIENT_SECRET | bastion/db/keycloak | gateway, worker | vault-export → .env.vault |
| MINIO_ROOT_PASSWORD | bastion/db/minio | minio, minio-init | vault-export → .env.vault |
| AUDIT_WITNESS_SECRET_KEY | bastion/db/minio | minio-init | vault-export → .env.vault |
| JOB_SIGNING_SECRET | bastion/app/jwt | gateway, worker | not wired yet |
| APPROVAL_HMAC_SECRET | bastion/app/jwt | gateway, worker | not wired yet |
| OPENROUTER_API_KEY | bastion/app/oauth | omniroute | not wired yet |
| OMNIROUTE_API_KEY | bastion/app/oauth | gateway, worker | not wired yet |
| LLAMA_API_KEY | bastion/app/oauth | omniroute, llama-cpp | not wired yet |

## Makefile targets

| Target | What it does |
|--------|-------------|
| `make vault-up` | Generate the cert if missing, build, start Vault, bootstrap and seed |
| `make vault-down` | Stop Vault containers (the data volume persists) |
| `make vault-shell` | Open an interactive shell in the Vault image |
| `make vault-export` | Materialise infra creds into gitignored `.env.vault` (mode 600) |
| `make vault-list` | List secret paths under `bastion/` (no values) |
| `make vault-rotate SECRET=db/postgres` | Patch a secret value (paths are relative to `bastion/`) |

`vault-export` fails loudly and deletes `.env.vault` if any value comes back
empty, so a sealed or unseeded Vault cannot leave you with a plausible-looking
file full of blanks.

## Environment variables

The app services need only:

```
VAULT_ADDR=https://vault:8200
VAULT_TOKEN=***
```

Everything else comes from Vault. The dev token
(`dev-root-token-bastion`) is created by the bootstrap for local development
only — rotate it before any staging or production use. The `vault` container
also sets `VAULT_SKIP_VERIFY`, because the dev certificate is self-signed.

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
