---
name: Local stack
description: Bring up, inspect or debug the Docker Compose stack — service ports, health probes, Keycloak dev token, model load times, and the failure modes that look like bugs. Use when starting or rebuilding containers, when a service is unhealthy or a port is taken, or when a request fails with 503 or connection refused.
---

# Local stack — bring up, inspect, debug

The stack is `gateway` + `worker` (one image) plus `db`, `redis`, `keycloak`,
`omniroute`, `llama-cpp`, `otel-collector`, `pgadmin` and `redis-ui`.

## Ports

Every published port is bound to `127.0.0.1` and parameterised, so read the
value rather than assuming the default.

| service | variable | default |
| --- | --- | --- |
| gateway | `GATEWAY_PORT` | 8000 |
| db | `POSTGRES_PORT` | 5432 |
| redis | `REDIS_PORT` | 6379 |
| keycloak | `KEYCLOAK_PORT` | 8080 |
| omniroute | `OMNIROUTE_PORT` | 8001 |
| llama-cpp | `LLAMA_PORT` | 8002 |
| pgadmin | `PGADMIN_PORT` | 5050 |
| redis-ui | `REDIS_UI_PORT` | 5540 |

`.env` in the active worktree is authoritative. This host overrides
`REDIS_PORT`, so `6379` alone proves nothing; `docker compose ps` shows the
binding that exists, and `docker compose config` shows the resolved file.

## Bring up and rebuild

```bash
docker compose up -d                                            # whole stack
docker compose build gateway                                    # worker reuses the image
docker compose up -d --no-deps --force-recreate gateway worker  # after a code change
docker compose ps --format '{{.Service}}: {{.Status}}'
```

## Health

```bash
curl -s http://127.0.0.1:${GATEWAY_PORT:-8000}/health          # liveness
curl -s http://127.0.0.1:${GATEWAY_PORT:-8000}/health/ready    # readiness
docker compose logs --tail=50 gateway
```

Readiness failing usually means `db` or `redis` is not healthy yet, not that the
gateway is broken.

## Dev token

The password-grant recipe lives in `README.md` (Local Development → dev token)
and `DEMO.md`; the realm is `bastion`, the CLI client is `bastion-cli`, and the
seeded users are `alice`, `bob`, `carol` and `breakglass`. Request a token from
there rather than retyping one from a transcript, and do not write the password
into any file — `secrets` skill covers the handling.

## Failure modes worth knowing

- **`llama-cpp` takes minutes on first start.** It loads a 7B GGUF; a 503 on a
  `CONFIDENTIAL` route before it is ready is expected, not a routing bug.
- **A port is "taken" by the previous run.** `docker compose down` first; `down -v`
  also destroys the audit ledger volume, so only use it when the data is
  disposable.
- **Remote trace export is paused** while `OTEL_REMOTE_EXPORT_CONFIG` is unset;
  spans still reach the local collector, so absence from Langfuse is not a
  regression.
- **The stack is loopback-only by design.** Reach it from the host; a container
  cannot call `127.0.0.1` of the host.

## Done

`docker compose ps` shows every service `healthy` (or `running` where there is no
healthcheck) and `/health/ready` returns 200.
