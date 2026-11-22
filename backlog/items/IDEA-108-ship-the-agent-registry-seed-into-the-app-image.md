### IDEA-108: Ship the agent registry seed into the app image or mount it

- status: inbox
- priority: P2
- phase: v0.5
- area: infra
- tags: agents, rbac, docker, migrations
- depends-on: -
- spec: ADR-027
- created: 2026-11-22
- updated: 2026-11-22
- source: live debugging of an MCP token, 2026-11-22

**Problem**

`seed_agent_registry` (`db/migrate.py:62`) reads `config/agents/registry.json` (`db/agents.py:15`) and
logs `WARNING: Agent registry seed is absent; no rows seeded` when it is missing. In a container it is
always missing: `Dockerfile` copies `db/`, `gateway/`, `agent/`, `docs/` and a few single files, but not
`config/`, and no service mounts `./config/agents`. Confirmed on the running stack —
`docker run --rm --entrypoint sh bastion-agent:local -c 'ls config'` answers `No such file or directory`
— and `select * from agent_registry` is empty after a successful `migrate` run.

The consequence is quiet and total: every agent token is refused `403 unregistered_agent` at ingress
(`gateway/auth/agents.py:_refusal`), including on the new `/mcp` surface, so the ADR-027 agent capability
is unusable in any Docker deployment while passing every test, because tests build their own rows.

**Outcome**

A deployed stack seeds the registry from the file the repository already tracks, and a missing seed is
loud rather than a warning. Either the image copies `config/agents` (and any sibling the runtime reads
by relative path) or the `migrate` and `gateway`/`worker` services mount it read-only; the seed stays
insert-only, so a row an operator suspended is never resurrected.

**Acceptance**

- [ ] A containerised `make up` on an empty database leaves one `agent_registry` row per
      `config/agents/registry.json` entry, asserted by a test or a scripted check rather than by reading logs
- [ ] `migrate` fails (or warns in a way the gate sees) when the seed path is missing, so the absent file
      cannot ship unnoticed again
- [ ] `scripts/gate.sh` passes and the fix is recorded where it belongs (`Dockerfile` or `docker-compose.yml`)

**Notes**

- Found while verifying `/mcp` by hand: the token was valid and carried `bastion-mcp`, but the surface
  would still have answered `403` because the registry table was empty.
- Local workaround used to unblock the manual check: the row was inserted with `psql` using the values in
  `config/agents/registry.json`. That is not a fix — a fresh `make up` reproduces the gap.
- Related: IDEA-061's phase 2 needs the registry row to be authoritative for upstream tool allowlists, so
  an empty registry would also hide the upstream surface later.
