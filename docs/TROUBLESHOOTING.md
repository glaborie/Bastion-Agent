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

## Host processes get `Connection reset by peer` from Postgres or Redis

**Symptom.** After a `docker compose restart`, a `docker compose up -d` or a
Docker daemon restart, everything inside the containers works — `psql`,
`redis-cli`, healthchecks, the gateway — but Python clients on the host fail with
`ConnectionResetError: [Errno 104]` during connect or AUTH. `asyncpg`, `redis-py`
and even a raw socket to `127.0.0.1:5432`/`:26379` are affected. Clients run with
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
