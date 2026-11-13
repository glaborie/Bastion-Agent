### IDEA-039: Run Uptime Kuma as a profile-gated sidecar that watches container health

- status: inbox
- priority: P2
- phase: v0.5
- area: infra
- tags: monitoring, docker, uptime, healthcheck, availability
- depends-on: -
- spec: ADR-001
- created: 2026-11-12
- updated: 2026-11-12
- source: session request on 2026-11-12 ("set up and deploy uptime kuma to monitor the health of the containers, configure it as a side car with profile infra")

**Problem**

Six of the eight default services declare a Compose healthcheck — `gateway` (`docker-compose.yml:166`), `db` (`:216`), `redis` (`:281`), `keycloak` (`:338`), `omniroute` (`:379`) and `llama-cpp` (`:430`) — while `worker` (`:183`) and `otel-collector` (`:459`) have none, the collector's omission being deliberate because the distroless image has no shell to probe (`:160-163`). Those states only gate `depends_on` at startup and colour `docker compose ps`: nothing records a transition, keeps a history or tells a person, so a container that dies overnight is invisible until someone types `docker compose ps` the next morning. The only runtime telemetry is the OTel trace pipeline (ADR-014), which carries payload-free request spans and no availability record, and `gateway/routers/health.py` serves `/health` and `/health/ready` (database only) that nothing consumes after boot. No monitoring service, profile or monitor definition exists: `uptime` and `kuma` have no hit in the tree, and the only `prometheus` hit is `wiki/API-Reference.md:36`, which documents a `/metrics` endpoint the gateway does not serve.

**Outcome**

`docker compose --profile infra up -d` starts one digest-pinned Uptime Kuma sidecar with a named volume and a loopback-only port, and a committed monitor file plus an idempotent seed step gives it one monitor per default service that actually exposes a probe: `gateway` `/health` and `/health/ready`, `db:5432` and `redis:6379` as TCP, Keycloak's management health endpoint on `:9000` (`KC_HEALTH_ENABLED` is already on, `docker-compose.yml:329`) or `/realms/bastion`, `omniroute` `/api/health`, and `llama-cpp` TCP `:8080` with a start period long enough for a model load. It never mounts the Docker socket and never reads engine health directly, so the monitors observe the same endpoints a client would; the worker's disposition is decided and recorded (a queue or Redis signal, or explicitly unmonitored) instead of left accidental. The default profile, every existing healthcheck and the `bastion-net` topology are unchanged, the new image enters the Trivy inventory, and the docs state what is watched, what is not, and that a monitor on the same host cannot report a host, daemon or monitor outage. Notification delivery is optional and configured from `.env`, never committed.

**Acceptance**

- [ ] `docker compose --profile infra config --services` lists the monitor service and nothing else new, `docker compose config` without the profile is unchanged (a diff touches no default-profile service), and the service declares a digest-pinned image, a named volume, a `127.0.0.1:<port>` mapping only, `cap_drop: [ALL]` and `no-new-privileges:true`
- [ ] `grep -n "docker.sock" docker-compose.yml` returns nothing, the monitor service is not `privileged`, and a test asserts both so the compose healthchecks stay the engine's rather than being proxied through a socket
- [ ] `scripts/seed_uptime_kuma.py` (or the named equivalent) applies `config/uptime-kuma/monitors.json` idempotently: a test runs it twice against a recording client and asserts the same monitor set, and the file names one monitor per probe listed in **Outcome** plus the worker's recorded disposition
- [ ] A down transition is observable end to end: with the profile up, `docker compose stop redis` flips its monitor to DOWN within the configured interval and `docker compose start redis` returns it to UP, and the evidence is captured without any notification credential
- [ ] Monitoring state survives `docker compose restart uptime-kuma`: the monitor set and its history are still present through the named volume
- [ ] The initial admin credential is read from a required `.env` key like `POSTGRES_PASSWORD` (`${...:?set ... in .env}`) and appears in neither `.env.example`'s default nor any committed file, asserted by a test that fails on a literal
- [ ] `uv run pytest tests/test_compliance_scan.py -q` passes with the image inventory updated for the new reference (precedent: IDEA-026), or the ADR records why it is excluded from the scan set
- [ ] `README.md` and `docs/TROUBLESHOOTING.md` document the command, the URL, the seed step, the `infra` profile, what is and is not monitored (worker, host, Docker daemon, model quality), and that OTel traces remain the detailed runtime telemetry; a new ADR records the component, the profile convention and the socket-free rule, and `uv run python scripts/check_adrs.py` passes
- [ ] `uv run pytest -q`, `ruff check .`, `ruff format --check .`, `mypy`, `pylint`, `check_backlog.py --check`, `validate_tool_catalog.py --check`, `validate_rbac.py` and `recalculate_dread.py --check` stay green

**Notes**

- Deduplication: grepped `BACKLOG.md`, `docs/adr/`, `docker-compose.yml`, `README.md` and `THREAT_MODEL.md` for `uptime`, `kuma`, `monitor`, `availability`, `prometheus` and `grafana`. Nothing covers availability monitoring: IDEA-022 (done, ADR-017) is runtime *process* detection, IDEA-026/ADR-014 is trace export, IDEA-019/025 are image scanning, IDEA-031 is threat-model drift, and the `monitoring` tag on IDEA-022 names Falco alerts rather than uptime. No item was merged and no id was reused.
- `spec: ADR-001` names the record the sidecar must fit rather than a decision that permits it: the Context fixes one compose stack per host (`docs/adr/ADR-001.md:11`) and decision 1 excludes "sidecar proxies" (`:15`); a monitoring sidecar is not a proxy, but that reading must be written down rather than assumed, which is why the new ADR is part of the acceptance. Nothing else in `docs/adr/` decides monitoring.
- Classification: `P2`/`v0.5`/`infra`. New capability with nothing broken today — the stack runs, healthchecks exist and no stated invariant is at stake — so not `P0`/`P1`; ADR-008 decision 5 freezes features inside a phase and the current phase is v0.3. No ADR-008 line names monitoring; v0.5 "Production readiness" is the nearest home, and triage may move it to v0.3 alongside the other infrastructure work or reject it as unnecessary for a single-host demo. `area: infra` because every edited line lands in compose, `config/`, `.env.example`, a seed script and the docs.
- Profile-name question for triage: the request says `infra`, but the existing profiles are `pgadmin`, `redis-ui`, `compliance` and `security`, and PKI is a separate `docker-compose.pki.yml` override (IDEA-023). Whether monitoring joins one of those, takes `infra`, or uses an `observability` name should be settled with the ADR that records the convention instead of growing a fourth naming style by accident.
- The honest design constraint: Uptime Kuma speaks HTTP/TCP/ICMP, not Docker health states, so the monitors must target endpoints over `bastion-net` and the two services without a listener stay outside it unless a signal is invented. `llama-cpp` takes minutes to load on this host (`start_period: 180s`, `:436`), so its monitor needs a matching grace period or it reports DOWN on every restart, and `otel-collector` has no port to probe at all.
- Deliberately out of scope, each a follow-up rather than bundled work: Prometheus/Grafana metrics scraping and the stale `/metrics` claim in `wiki/API-Reference.md:36`; paging or an external dead-man's-switch prober (a monitor on the same host cannot report its own host's failure); adding healthchecks to `worker` and `otel-collector`; per-service SLOs and alert routing; and any dashboard integration with the existing approval UI.
- Intake only: no compose, `config/`, script, `.env.example`, document or ADR change is part of this capture, and the idea was not implemented in the turn that produced it.
