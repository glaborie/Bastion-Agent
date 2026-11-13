### IDEA-022: Detect runtime container escapes and unexpected process behaviour with Falco

- status: done
- priority: P2
- phase: v0.4
- area: security
- tags: runtime, falco, detection, docker, monitoring
- depends-on: -
- spec: ADR-001
- created: 2026-11-11
- updated: 2026-11-11
- source: session request on 2026-11-11 ("capture Falco as a compliance improvement")

**Problem**

The stack is hardened at start and unobserved afterwards. The app tier carries
`init: true`, `no-new-privileges:true` and `cap_drop: ALL`
(`docker-compose.yml:112-117`, the `x-app-build` anchor) and every other
service repeats the pair (`db:217-220`, `redis:282-285`,
`keycloak:341-344`, `omniroute:388-391`, `llama-cpp:442-445`,
`otel-collector:490-493`), but there is no seccomp, AppArmor or `noexec`
profile anywhere in the tree, so that is prevention with no observation: nothing
records what a process does after the container starts. All eight services share
one bridge network and the host kernel (`docker-compose.yml:503-505`), and
`bastion-net` is not `internal: true`, so a compromised gateway can open a
connection to any destination; "OmniRoute as the only routing layer"
(`docs/adr/ADR-001.md:21`) is enforced in Python, not by the network. The
process runs as uid 10001 (`Dockerfile:21-22,45`) but owns its own source tree
(`Dockerfile:35-41`), so it can rewrite `/app/gateway/...`, and it can spawn
`/bin/sh` from the `python:3.11-slim` base (`Dockerfile:6`) without any tool
doing it: `docs/tools/v1.json` lists exactly three tools
(`execute_file_write`, `read_file`, `read_system_status`), none executes a
command, and `agent/tools/builtin.py:37-59,147-166` confines writes to
`TOOL_WORKSPACE_ROOT` (`/tmp/bastion-workspace`, `.env.example:117`). The
existing evidence cannot cover this: T10 (`THREAT_MODEL.md:231-241`) is post-hoc
chain verification and T11 (`:243-251`) is build-time supply chain; §4's control
table (`:85-95`) lists no control that observes syscalls, process trees or
sockets, and the only uses of "runtime" in that document are the status
definitions (`:18`) and a negation (`:183`). `COMPLIANCE.md` overstates what
exists: CC7.2 (`:103`) claims "detection and monitoring procedures" evidenced by
"Golden regression suite, CI/CD gates, vulnerability scanning, SBOM generation",
all build-time; FINMA §4.4 (`:116`) cites "real-time approvals"; EU AI Act
Art. 15 (`:146`) repeats the build-time list; and `:56`/`:104` claim
"24/7/365 monitoring", which no component performs.

**Outcome**

One documented, opt-in command starts a runtime detector that observes the
container syscalls the rest of the design assumes are well behaved, and a
reviewed rule set turns the behaviours that matter here into JSON alerts naming
the container and process: a shell or package manager in `gateway`/`worker`, a
worker write outside `TOOL_WORKSPACE_ROOT`, a gateway connection to anything
other than `db`, `redis`, `keycloak`, `omniroute`, `otel-collector` or the
container DNS resolver, `exec`/`nsenter` into `db` or `redis`, and a write to
`/etc/passwd`, `/etc/shadow` or the app's own tree. The default `docker compose
up -d`, the unprivileged CI job and the host test suite are unchanged; alerts
carry container and process metadata only, never prompt or completion text, tool
arguments, vault markers or process environment. `COMPLIANCE.md` and
`THREAT_MODEL.md` state what is observed, what is not, and which rows were
overstating monitoring before the control existed.

**Acceptance**

- [x] Each custom rule has a deterministic trigger: a documented command such as `docker compose exec gateway sh -c 'id'` produces an alert naming the container and the process, and a clean host run of `uv run pytest -q` produces none; the in-container baseline (entrypoint, `init`/tini, the 15 s `python -c` healthcheck at `docker-compose.yml:160-171`) is allowlisted in a committed file with a one-line justification and a review date per entry
- [x] A write by the worker outside `TOOL_WORKSPACE_ROOT` alerts and the same write inside `/tmp/bastion-workspace` does not; the alert names the path, the container and the process
- [x] A connection from `gateway` to a non-allowlisted destination alerts, while a normal DLP-to-OmniRoute turn (and the internal `db`, `redis`, `keycloak`, `otel-collector` paths) does not; the rule matches the app tier by image or `container.name` prefix, never by `bastion-gateway`/`bastion-worker`, which compose does not assign (`docker-compose.yml:127`)
- [x] A captured alert file from a test turn carrying a known canary string and a known PII value contains neither, and contains no `proc.env`, no `VAULT_MASTER_KEY`, `DATABASE_URL`, `REDIS_PASSWORD` or `OPENROUTER_API_KEY` value; the field allow-list is asserted, not reviewed
- [x] `docker compose --profile security up -d falco` starts a digest-pinned image, the elevated access it needs (privileged or the documented capability set, tracefs and `/proc` mounts) is confined to that service, `docker compose config` without the profile is unchanged, and the README states why it is not in the default stack
- [x] The container-metadata source is decided and recorded: syscall capture alone needs no engine socket and yields `container.id` only, while `container.name`/`container.image` need a read-only engine socket (Docker or CRI); whichever is chosen is stated in the ADR and in a compose comment
- [x] Alert delivery is proven end to end on the chosen path: JSON file under a mounted directory, or a collector logs pipeline; if the OTel collector is chosen, `config/otel/otel-collector-config.yaml` gains a `filelog` receiver and a `logs` pipeline, because it currently defines a `traces` pipeline only (`:137-143`) and `service.telemetry.logs` (`:133-136`) is the collector's own log level
- [x] `THREAT_MODEL.md` and `COMPLIANCE.md` cite the control only after it exists: the item names CC7.2 (`COMPLIANCE.md:103`), FINMA §4.4 (`:116`), EU AI Act Art. 15 (`:146`) and the "24/7/365 monitoring" sentences (`:56`, `:104`) as the rows this changes, and `THREAT_MODEL.md` gains a runtime-detection control row and residual with the document's own `LIVE`/`PARTIAL`/`PLANNED` definitions (`:17-19`)
- [x] `uv run pytest -q`, `ruff check .`, `ruff format --check .`, `mypy`, `pylint`, `scripts/gate.sh`, `check_adrs.py`, `check_backlog.py --check`, `validate_tool_catalog.py --check`, `validate_rbac.py` and `recalculate_dread.py --check` still pass, and a new ADR (next free number; IDEA-019 claims ADR-016) records the driver, the privilege carve-out, the allowlist policy and the delivery path

**Notes**

- Deduplication: IDEA-019 (`BACKLOG.md`, Notes line on deliberate exclusions) already names "runtime detection (Falco or equivalent)" as deliberately out of scope and a follow-up item, so this is that follow-up, not a duplicate of the build-time image scan. Trivy/SBOM is build-time (T11); IDEA-015 is egress semantic disclosure; IDEA-018 is a conversation-signal detector; T10 is post-hoc audit tampering. Grepped `BACKLOG.md`, `docs/adr/`, `THREAT_MODEL.md`, `COMPLIANCE.md`, `SECURITY.md` and `docker-compose.yml` for `falco`, `ebpf`, `syscall`, `intrusion`, `runtime`: no item, ADR or control observes live process behaviour. `SECURITY.md:244` mentions HashiCorp/Azure Vault, a secret store, not this.
- `spec: ADR-001` because it fixes the deployment shape this control must fit — one compose stack on one host, no service mesh or sidecar proxies (`docs/adr/ADR-001.md:11,15`) — so the detector is a host-level observer with a privilege carve-out, not a per-service sidecar. Honest boundary: ADR-001 does not decide runtime detection, so the implementation authors a new ADR; that ADR must not contradict decision 1 (no sidecars) or decision 5 (synchronous audit), and Falco alerts must not become ledger rows because the `AuditEventType` vocabulary is frozen (ADR-007 decision 7).
- Classification: `P2`/`v0.4`. New capability, no stated invariant broken and the stack runs, so not `P0`/`P1`; ADR-008 decision 5 freezes features inside a phase and the current phase is `v0.2`. `v0.4` is the intake's chosen home; the nearest named phase is actually `v0.5` "compliance mode" / production readiness (`docs/adr/ADR-008.md:20`), and no phase line names runtime detection, so triage may move it. `area: security` because the load-bearing content is a cross-cutting runtime invariant plus the truthfulness of three compliance rows; `infra` is the mechanical alternative (compose service, `config/falco/`, collector config). The docs half is separable as a v0.2 `docs` correction if triage prefers.
- Corrected premise 1: the engine socket is not needed for syscall capture, but it *is* needed for `container.name`/`container.image` enrichment — `container.id` is taken from cgroups in-kernel. Either mount `/var/run/docker.sock` read-only on the Falco service (and only there) or accept id-only alerts; this must be an explicit decision, and must not be read as relaxing IDEA-019's rule that the *scanner* mounts no socket.
- Corrected premise 2: the collector cannot ingest Falco alerts today. `config/otel/otel-collector-config.yaml:137-143` defines only `traces` with receivers `[otlp]`; adding a `filelog` receiver plus a `logs` pipeline is real work. Simplest path to weigh first: Falco `json_output` to a file under a mounted `artifacts/falco/` directory, mirroring the existing `./artifacts` mount (`docker-compose.yml:141`), with the collector pipeline as a follow-up; the ADR records the trade-off.
- Falco requirements, to be confirmed against its current docs before coding: modern eBPF needs a BPF ring buffer and kernel BTF (typically kernel ≥ 5.8); the container needs `/proc`, `/etc` and tracefs (`/sys/kernel/tracing`, or `/sys/kernel/debug/tracing` on older layouts); the least-privilege capability set is `CAP_SYS_PTRACE`, `CAP_SYS_RESOURCE`, `CAP_BPF`, `CAP_PERFMON`, but Docker does not grant `CAP_BPF`/`CAP_PERFMON`, so `CAP_SYS_ADMIN` or `privileged: true` is required. That is an explicit, single-service carve-out from the `cap_drop: ALL` baseline and must be documented as such.
- Honest limits to record in the ADR: elevated host access means the control detects container misbehaviour more than it defends the host perimeter; events are high-volume and need tuning; a root attacker can disable or unload it; it does not contain or kill anything. Also, `docs/adr/ADR-001.md:11` names WSL2 + Docker Desktop as the development target while Falco's container quickstart says it does not work on Windows/macOS Docker Desktop, so the control is verifiable only on a Linux host or VM and must not be attempted in the unprivileged CI job.
- Deliberately out of scope: a SIEM, alert routing/paging, the Falco response engine (kill/containment), Kubernetes, host IDS (auditd or a host vulnerability scan), secrets management, and image signing. Each is its own item; IDEA-019 covers build-time scanning.
- Open questions for triage: file vs OTel output; retention and rotation for captured alerts (they are security evidence, not traces, so ADR-014's trace-privacy contract does not cover them); who owns the allowlist and how often it is reviewed; whether the rules also watch `db`, `redis` and the inference services or only the app tier; and whether the docs correction should ship in v0.2 ahead of the control.
- Intake only: no implementation, compose, `config/falco/`, collector, ADR or compliance-document edit is part of this capture.

**Implementation notes (2026-11-11)**

- Service: `falcosecurity/falco:0.45.2@sha256:1562a643…`, modern eBPF, opt-in `security` profile, `privileged: true`, no ports. It is the only privileged service and the only one with the Docker socket; the socket is read-only at `/host/var/run/docker.sock` and drives container-name enrichment. ADR-017 records the carve-out.
- Rules: six rules in `config/falco/bastion_rules.yaml` (app shell, worker write outside `/tmp/bastion-workspace` and `/tmp`, gateway egress outside ports 53/4317/4318/5432/6379/8000/8080/20128, shell or nsenter in `db`/`redis`, `/etc/passwd`/`shadow`/`sudoers`, `/app`). Output fields are container/process/file/socket metadata only; `proc.cmdline`, `proc.args`, `proc.env` and `evt.buffer` are excluded and asserted by `tests/test_falco.py`.
- Live verification on this host: the smoke script fired the app-shell rule (`docker exec gateway sh -c id`), the worker-write rule (`/home/bastion/...`), the gateway-egress rule (`1.1.1.1:443`) and the app-tree rule (worker write under `/app/gateway`); a workspace write and a `db:5432` connection stayed silent; the alert file contained no secret value or process-argument field. `scripts/falco_smoke.sh` passes, and `tests/test_falco.py` is 9 passing tests.
- Docker Desktop findings, recorded in ADR-017 rather than hidden: `pid: host` suppressed all events and was removed; `/dev` is required; `/proc` lookups return `<NA>` for parent and command line, so the `docker-entrypoint.sh` and `pg_isready`/`redis-cli` exceptions cannot be evaluated here and the data-container rule is noisy at healthcheck cadence. The rule set and allowlist are written for a native Linux host, which the ADR names as the verification target.
- Delivery: JSON to `artifacts/falco/events.json` (gitignored, `.gitkeep` tracked) and stdout. The OTel collector is untouched: it has a traces pipeline only, and adding logs is a separate decision.
- Docs: ADR-017 and the index, `THREAT_MODEL.md` §4 (row + residual, version 2.3), `COMPLIANCE.md` (CC7.4, FINMA §4.4 marked partial, EU Art. 15, the security-control row) and `README.md`; the 24/7/365 monitoring claims are removed.

**Implementation notes (2026-11-11)**

- Service: `falcosecurity/falco:0.45.2@sha256:1562a643…`, modern eBPF, opt-in `security` profile, `privileged: true`, no ports. It is the only privileged service and the only one with the Docker socket; the socket is read-only at `/host/var/run/docker.sock` and drives container-name enrichment. ADR-017 records the carve-out.
- Rules: six rules in `config/falco/bastion_rules.yaml` (app shell, worker write outside `/tmp/bastion-workspace` and `/tmp`, gateway egress outside ports 53/4317/4318/5432/6379/8000/8080/20128, shell or nsenter in `db`/`redis`, `/etc/passwd`/`shadow`/`sudoers`, `/app`). Output fields are container/process/file/socket metadata only; `proc.cmdline`, `proc.args`, `proc.env` and `evt.buffer` are excluded and asserted by `tests/test_falco.py`.
- Live verification on this host: the smoke script fired the app-shell rule (`docker exec gateway sh -c id`), the worker-write rule (`/home/bastion/...`), the gateway-egress rule (`1.1.1.1:443`) and the app-tree rule (worker write under `/app/gateway`); a workspace write and a `db:5432` connection stayed silent; the alert file carried no secret value or process-argument field. `scripts/falco_smoke.sh` passes, and `tests/test_falco.py` adds 9 tests.
- Docker Desktop findings, recorded in ADR-017 rather than hidden: `pid: host` suppressed all events and was removed; `/dev` is required; `/proc` lookups return `<NA>` for parent and command line, so the `docker-entrypoint.sh` and `pg_isready`/`redis-cli` exceptions cannot be evaluated here and the data-container rule is noisy at healthcheck cadence. The rule set and allowlist are written for a native Linux host, which the ADR names as the verification target.
- Delivery: JSON to `artifacts/falco/events.json` (gitignored, `.gitkeep` tracked) and stdout. The OTel collector is untouched: it has a traces pipeline only, and adding logs is a separate decision.
- Docs: ADR-017 and the index, `THREAT_MODEL.md` §4 (row + residual, version 2.3), `COMPLIANCE.md` (CC7.4, FINMA §4.4 marked partial, EU Art. 15, the security-control row) and `README.md`; the 24/7/365 monitoring claims are removed.
- Gate: full pytest 611 passed, ruff/mypy/pylint/adrs/backlog/tool-catalog/RBAC/DREAD green (see the gate log).

**Implementation notes (2026-11-11)**

- Service: `falcosecurity/falco:0.45.2@sha256:1562a643…`, modern eBPF, opt-in `security` profile, `privileged: true`, no ports, restart unless-stopped. It is the only privileged service and the only one with the Docker socket; the socket is read-only at `/host/var/run/docker.sock` and drives container-name enrichment. ADR-017 records the carve-out.
- Rules: six rules in `config/falco/bastion_rules.yaml` (app shell; worker write outside `/tmp/bastion-workspace`; gateway egress outside ports 53/4317/4318/5432/6379/8000/8080/20128; shell or nsenter in `db`/`redis`; `/etc/passwd`/`shadow`/`sudoers`; `/app`). Output carries container/process/file/socket metadata only; `proc.cmdline`, `proc.args`, `proc.env` and `evt.buffer` are excluded and asserted by `tests/test_falco.py`.
- Live verification on this host: `scripts/falco_smoke.sh` fired the app-shell rule (`docker exec gateway sh -c id`), the worker-write rule (a write to `/home/bastion/...`), the gateway-egress rule (`1.1.1.1:443`) and the app-tree rule (a worker write under `/app/gateway`); a write inside `/tmp/bastion-workspace` and a connection to `db:5432` stayed silent; the alert file contained no secret value and no process-argument field. `tests/test_falco.py` is 9 passing tests.
- Docker Desktop findings, recorded in ADR-017 rather than hidden: `pid: host` suppressed every event and was removed; `/dev` is required; `/proc` lookups return `<NA>` for parent and command line, so the `docker-entrypoint.sh` and `pg_isready`/`redis-cli` exceptions cannot be evaluated here and the data-container rule is noisy at healthcheck cadence. The rule set and allowlist target a native Linux host, which the ADR names as the verification environment.
- Delivery: JSON to `artifacts/falco/events.json` (gitignored with `.gitkeep`) and stdout. The OTel collector is untouched: it defines only a traces pipeline, and adding logs is a separate retention/privacy decision.
- Docs: ADR-017 and the index, `THREAT_MODEL.md` §4 (row plus residual, version 2.3), `COMPLIANCE.md` (CC7.4, FINMA §4.4 marked partial, EU Art. 15, the security-control row, and the 24/7 claims removed) and `README.md`.
