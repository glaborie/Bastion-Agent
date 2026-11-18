# Troubleshooting

Symptoms that cost real time before they were diagnosed. Add to this file when a
failure takes more than a few minutes to explain; a note here is cheaper than
re-deriving it in the next session.

## The gateway logs `CSRF check failed` and a form does nothing

**Symptom.** `{"logger": "gateway.auth.rbac", "message": "CSRF check failed",
"subject": "…", "path": "…", "token_presented": true}` after a sign-in, and the
click that produced it answers `403 CSRF token missing or invalid` (an htmx
caller now receives `HX-Redirect: /dashboard` instead and reloads).

**Cause.** `token_presented: true` with the right subject is a stale document:
CSRF tokens are per session, a sign-in replaces the single `bastion_session`
cookie, and a tab rendered before that re-login keeps the old token while the
browser sends the new cookie. `token_presented: false` is a client that never
sent one — a script with a session cookie, which is meant to be refused.

**Fix.** Reload the tab; the page re-renders with the current session's token.
Sign-out now revokes every session of the operator (`delete_all_for_subject`),
so a second browser cannot outlive it, but sessions created before this change
still expire only by TTL. List what is tracked:

```bash
docker compose exec redis sh -c \
  'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning --scan --pattern "auth:subject-sessions:*"'
```

## `docker compose up` aborts with `Could not attach to network …: network … not found`

**Symptom.** `docker compose up -d` starts db, Redis, Keycloak and migrate, then
stops with

```
Error response from daemon: failed to set up container networking:
Could not attach to network 3cdb3d40…: rpc error: code = NotFound desc:
network 3cdb3d40… not found
```

and the services that failed sit in `Created`. Recreating them with
`docker compose rm -sf` does not help, because the next `up` reuses them.

**Cause.** A container stores its network binding by *id*. When a network is
deleted and recreated under a long-lived container — a Docker Desktop restart, a
`docker network prune`, a chaos run — the stored endpoint id survives while the
network with that id does not, and the daemon refuses to attach. `docker network
ls` shows the network under its current id, so the id in the error appears
nowhere, and `docker inspect <container>` still names the network correctly. The
stale containers are the ones created before the network was recreated;
`docker inspect <name> --format '{{json .NetworkSettings.Networks}}'` shows the
old `NetworkID` on exactly those.

**Fix.** Remove the containers bound to the dead id; compose recreates them on
the current network, and volumes are untouched:

```bash
uv run python scripts/dev/compose_preflight.py --dry-run   # which ones
uv run python scripts/dev/compose_preflight.py             # remove them
```

`make up` runs the same preflight first, so the check no longer has to be
remembered. Observe the rule: deleting the *network* while containers are up is
what starts this, so `docker network prune` on a running stack is not safe.

## The gateway exits with `injection-guard model not found`

**Symptom.** `bastion-agent-gateway-1` restarts with

```
agent.routing.classifier.ClassifierConfigurationError:
injection-guard model not found: models/prompt-injection-guard-small/onnx/model_quantized.onnx
```

and `ls models/` shows only the GGUF.

**Cause.** The classifier paths in `.env` point at the two pinned ONNX
repositories, which are gitignored and mounted read-only into gateway and worker.
Before IDEA-064 nothing in the stack created them, so a checkout that never ran
the download started correctly into a fail-closed error.

**Fix.** Let the stack fetch them; `models-init` runs before gateway and worker
and verifies each graph against `CLASSIFIER_*_MODEL_SHA256`:

```bash
docker compose up -d models-init          # shows the digest check
docker compose up -d gateway worker
```

On the host (tests that need the real graphs) use `make models`. If the fetch
fails with a digest mismatch, the pinned revision and the digest in `.env` have
drifted apart: update both in the same change rather than accepting the graph.
Set `HF_TOKEN` when Hugging Face rate-limits the download. `MODEL_PATH` values
left empty mean the deterministic rule fallback and no fetch at all.

**If the graphs exist but the gateway still exits with "model not found".**
`ls -l models/*/onnx/` shows `-rw-------`. The fetcher used to install the graph
with the mode `tempfile.mkstemp` gave it (0600), so the owner could read it and
the container's uid 10001 could not. `uv run python scripts/fetch_models.py` (or
`make models`) now sets 0644 on the graph and its sidecars, including files it
already verified, so one re-run repairs an existing checkout:

```bash
make models                              # verifies, and fixes the modes
docker compose restart gateway worker
```

## The first chat turn after a restart is slow

**Symptom.** The first `POST /v1/chat` after `docker compose up -d gateway`
takes seconds longer than every later turn, and the ledger shows the gap
between `INPUT_RECEIVED` and `DLP_REDACTION` — not between `DLP_REDACTION` and
`RESPONSE_SENT`. Before IDEA-067 the gateway log also showed `Loaded recognizer:
…` and `Presidio analyzer ready` *inside* the first request, 3-4 s after it
arrived.

**Cause.** The DLP analyzer (Presidio plus the spaCy pipelines per modelled
language) and the ONNX ensemble are expensive to build and used to be built by
whichever request arrived first.

**Fix.** Startup now builds both (`agent/warmup.py`, called from the gateway
`lifespan` and the worker `startup`), and the server does not accept traffic
until that returns: `/health/ready` reports `checks.guards` and a guard that
cannot be built aborts startup with `GuardWarmUpError: <guard> warm-up failed:
<ExceptionType>` instead of failing the first request. So this signature
appearing again means the process did not go through warm-up — a script that
builds its own DLP, or a code path that bypasses `create_app` — not a slow
model. If warm-up itself fails, read the step above it: a missing graph is the
`injection-guard model not found` failure, and `make models` repairs it.

## A merged feature does not exist at runtime

**Symptom.** Something that is on `master` — a module, an audit event, an
endpoint — never happens on the running stack, while the checkout and its tests
have it. A concrete case: a frustrated conversation writes no
`HANDOFF_REQUIRED` row and `/api/handoffs` stays empty, because
`agent.sentiment` is not in the image at all.

**Cause.** `make up` used to run `docker compose up -d`, which reuses whatever
image is tagged `bastion-agent:local`; it never rebuilt. A stack started after a
merge therefore ran code from before it. The giveaway:

```bash
docker compose exec gateway python -c "import agent.sentiment"   # ModuleNotFoundError
docker images bastion-agent:local --format '{{.CreatedAt}}'      # older than the merge
```

**Fix.** `make up` builds now, and a `docker compose up -d` you run yourself
needs `--build`. For a stack that is already running:

```bash
docker compose up -d --build gateway worker
```

The ledger cannot reconstruct the lost conversation: `INPUT_RECEIVED` stores a
digest, not the text, and the escrow that could decrypt it is off by default
(README, "Pre-production payload escrow").

## The dashboard says the upstream model is unavailable (OmniRoute 401 AUTH_002)

**Symptom.** `/v1/chat` returns 502 and the gateway logs
`agent.routing.client` "OmniRoute rejected the completion", model
`cloud-primary`, status `401`, code `AUTH_002` "Invalid API key". The OmniRoute
UI shows no keys, providers or combos, and its container log holds only startup
migration lines, so there is nothing to inspect upstream.

**Cause.** OmniRoute 3.8.53 keeps its SQLite store in `DATA_DIR` (`/app/data`).
The compose volume was mounted at `/root/.omniroute`, the pre-upgrade location,
so nothing the router read was persisted: its state lived in the container's
writable layer and every recreated container came up empty.

**Fix.** The volume is mounted at `/app/data` now. Recreate the router and
reconcile the contract:

```bash
docker compose up -d omniroute
uv run python scripts/omniroute_bootstrap.py --write-env   # rotates OMNIROUTE_API_KEY
docker compose up -d gateway worker
```

The bootstrap rewrites `OMNIROUTE_API_KEY` in `.env` and smoke-tests both
aliases, so a passing run says the router answers `local-llama` and
`cloud-primary`. A container created before the fix keeps a volume whose root
holds the old layout; remove it (`docker compose rm -sf omniroute`, then
`docker volume rm bastion-agent_omniroute_data`) rather than mounting it at the
new path, where the app's uid cannot write it.

## Host processes get `Connection reset by peer` from Postgres, Redis or MinIO

**Symptom.** After a `docker compose restart`, a `docker compose up -d` or a
Docker daemon restart, everything inside the containers works — `psql`,
`redis-cli`, healthchecks, the gateway — but Python clients on the host fail with
`ConnectionResetError: [Errno 104]` during connect or AUTH. `asyncpg`, `redis-py`
and even a raw socket to `127.0.0.1:5432`/`:26379`/`:9000` are affected. Clients run with
`docker run --network host` succeed, which makes it look like a library bug.

**Cause.** The published-port path (the userland proxy / NAT rules) survived the
restart in a half-open state. The server is fine; the mapping in front of it is
not.

**Fix.**

```bash
docker compose down
docker compose up -d
```

A single `docker restart <container>` sometimes fixes one service (it did for
Redis) but not the others, so recreate the stack rather than debugging the
client. Verify with:

```bash
docker run --rm --network host redis:7-alpine \
  redis-cli -h 127.0.0.1 -p 26379 ping   # NOAUTH, not a reset
```

**Do not** spend time comparing client libraries, disabling hiredis, or testing
RESP3 first — the reset happens for every client, including a bare socket.

## `trivy: unable to initialize cache: cache may be in use by another process`

Two Trivy invocations are sharing one `TRIVY_CACHE_DIR`. The scanner takes an
exclusive lock while it updates the vulnerability database.

**Fix.** Run analyses of the same tarball sequentially
(`scripts/trivy-scan.sh` does). Separate cache directories also work but
re-download the database per format, which costs more than the overlap saves.

## The backlog validator reports a duplicate id or a drifting `next-id`

The backlog is append-only and has one writer. Two captures that append
concurrently — for example two subagents — race on the id sequence and can
produce `IDEA-NNN` twice.

**Fix.** Run captures one at a time. `uv run python scripts/check_backlog.py
--write` now also points `next-id` at the highest allocated id plus one, so the
counter cannot be left stale after an interrupted capture. If a duplicate did
land, renumber the later item (never the earlier one) and re-run `--write`.

## The database-backed suite errors at fixture setup

`tests/conftest.py` needs `TEST_DATABASE_URL`, and the Redis integration tests
need `REDIS_TEST_URL`. Without them the affected modules skip; with a stale URL
they error. Check that the compose stack is up and that the `.env` passwords
match the running containers:

```bash
docker compose ps
docker exec bastion-redis printenv REDIS_PASSWORD
```

The east-west TLS tests (`tests/test_db_tls.py`) skip their live half unless the
`pki` profile is running and `PKI_TEST_DATABASE_URL`, `PKI_TEST_CA`,
`PKI_TEST_CERT` and `PKI_TEST_KEY` are set. Those skips are allow-listed in
`.github/workflows/ci.yml`; a new skip reason must be added there or the `tests`
job fails on the unexpected-skip gate.

## The `infra` monitor refuses to start, or the seed adds nothing

Compiling the profile fails with `UPTIME_KUMA_ADMIN_PASSWORD` unset, or the seed
exits `seed: login failed`. The password is intentionally absent from
`.env.example`: `scripts/seed_uptime_kuma.py` creates the account from `.env` on
a fresh instance, and a committed default would be a published password.

**Fix.** Set `UPTIME_KUMA_ADMIN_PASSWORD` in `.env` and start the profile again.
If the instance already exists and the password was rotated in `.env` but not in
the dashboard, log in with the old one or delete the volume
(`docker compose --profile infra rm -sf uptime-kuma && docker volume rm
bastion-agent_uptimekuma_data`) and reseed.

Two more shapes of the same symptom:

- **Every monitor is DOWN and the UI never loads.** The container is likely
  serving its interactive database chooser because `UPTIME_KUMA_DB_TYPE=sqlite`
  was dropped; `docker logs bastion-uptime-kuma` shows `Waiting for user action`.
- **`docker compose up` fails with `Bind for 127.0.0.1:3001 failed`.** Another
  process owns the port; set `UPTIME_KUMA_PORT` and pass the same value to the
  seed with `--url http://127.0.0.1:<port>`.

`seed: 0 added, 7 already present` is success: the seed converges and never
duplicates. Editing a monitor in the dashboard is not overwritten by a reseed,
so a retuned monitor keeps its history.

## Local gates are slow

```bash
scripts/gate.sh --changed              # pylint + pytest only for the diff vs origin/master
scripts/gate.sh --changed --base HEAD  # ... against another ref
scripts/gate.sh --no-tests             # lint, types and policy only
```

`--changed` diffs the working tree (uncommitted and untracked files included),
forces the full suite when a shared file changed (`conftest.py`, `settings.py`,
`db/models.py`, `docs/tools/v1.json`), and falls back to full rather than running
nothing when no test file maps to the diff. CI still runs the full set, so the
local shortcut never replaces the gate.
