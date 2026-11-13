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
