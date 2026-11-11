# Falco allowlist review

Every `exceptions:` entry in `config/falco/bastion_rules.yaml` must appear here
with a one-line justification and a review date. A test (`tests/test_falco.py`)
fails if an exception is missing from this table or if its review date has
passed.

| Exception | Rule | Justification | Review |
|---|---|---|---|
| `data_container_entrypoints` | Bastion shell or nsenter in a data container | PostgreSQL and Redis start through their image's shipped `docker-entrypoint.sh`; that shell is the documented startup path. | 2027-02-11 |
| `data_container_healthchecks` | Bastion shell or nsenter in a data container | Compose runs the `pg_isready` and `redis-cli` healthchecks through `sh -c`; those shells are the documented probe path. | 2027-02-11 |

## Scope notes (not exceptions)

- The application healthcheck uses the exec form (`CMD ["python", "-c", ...]`),
  so it spawns no shell and needs no entry here.
- `init: true` injects tini as PID 1, which executes the image command directly.
- The worker rule allows `/tmp` as Python scratch; tool writes are confined to
  `/tmp/bastion-workspace` by the tool layer, and a write to `/tmp` elsewhere is
  a residual documented in ADR-017 rather than an allowlist entry.
