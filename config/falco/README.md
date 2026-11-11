# Falco runtime detection

Falco watches the kernel syscalls of the running containers and alerts when a
process does something the stack's design says should never happen. It is the
runtime layer beside the build-time image scan (ADR-016) and the application's
own audit ledger: Trivy looks at what is *in* an image before it runs, the
ledger records what the application *reports*, and Falco sees what the process
*actually does*.

The service is opt-in because the modern eBPF probe needs a privileged
container. The decision, the privilege carve-out and the environment limits are
recorded in [ADR-017](../../docs/adr/ADR-017.md).

## What the rules catch

All rules live in [`bastion_rules.yaml`](bastion_rules.yaml).

| Rule | What it catches | Why it matters |
|---|---|---|
| Bastion shell spawned in an application container | `sh`, `bash`, `dash`, `ash`, `zsh` or `ksh` in `gateway`/`worker` | The app tier executes Python directly; a shell is a new process tree outside the documented tool surface. |
| Bastion worker write outside the tool workspace | A worker write outside `/tmp/bastion-workspace` (with `/tmp`, `/dev`, `/proc`, `/sys`, `/run` treated as runtime scratch) | `execute_file_write` is confined to the workspace; a write elsewhere is unexpected. |
| Bastion gateway egress outside the allowlist | A gateway connection whose destination port is not 53, 4317, 4318, 5432, 6379, 8000, 8080 or 20128 | The gateway should reach only the database, Redis, Keycloak, OmniRoute and the local collector; cloud providers are reached through OmniRoute, never directly. |
| Bastion shell or nsenter in a data container | A shell or `nsenter` in `bastion-db` or `bastion-redis` | Interactive access to the data containers is not part of the stack. |
| Bastion write to a sensitive system file | Writes to `/etc/passwd`, `/etc/shadow` or `/etc/sudoers` | No service in the stack writes account or privilege files at runtime. |
| Bastion application source tree modified | A write under `/app` in the application image | The runtime image is immutable; a write there means code or the virtualenv changed after start. |

Every `exceptions:` entry is reviewed in [`ALLOWLIST.md`](ALLOWLIST.md) with a
justification and a review date. `tests/test_falco.py` fails if an entry is
missing or its date has passed.

## What an alert contains

One JSON object per line, written to `artifacts/falco/events.json` and to the
container log. Fields are machine metadata only:

- `container.name`, `container.image.repository`
- `proc.pid`, `proc.name`, `proc.pname`
- `fd.name` (file path) or `fd.name`/`fd.sport` (socket)
- the rule name, priority, tags and event time

**Never included**: prompt text, completion text, tool arguments, tool output,
vault markers and their plaintext, `proc.cmdline`, `proc.args`, `proc.env`, or
`evt.buffer`. A shell command line can carry a tool argument or a secret, and a
runtime detector must not become a second place where that text lands.
`tests/test_falco.py` asserts the exclusion on every rule.

## Running it

```bash
# Start the opt-in profile (default `docker compose up` does not start it)
docker compose --profile security up -d falco

# Follow the JSON alert stream
tail -f artifacts/falco/events.json

# Prove the rules: positive triggers and negative cases
scripts/falco_smoke.sh
```

The service is `falcosecurity/falco:0.45.2`, pinned by digest, in the `security`
profile. It has no published port. `artifacts/falco/*` is gitignored with a
tracked `.gitkeep`; alerts are evidence, not source.

## Privileges and why they are confined

- `privileged: true` — the modern eBPF probe needs `CAP_BPF` and `CAP_PERFMON`,
  which Docker does not grant through `cap_add`. This is the only privileged
  service in the stack.
- `/proc`, `/etc`, `/dev` and `/sys/kernel/tracing` are mounted from the host.
  `/dev` is what makes the documented container invocation emit events;
  `/proc` is used for process metadata.
- `/var/run/docker.sock` is mounted read-only at `/host/var/run/docker.sock` for
  container-name enrichment and nowhere else. The Trivy scanner deliberately
  has no socket (ADR-016).
- There is no `pid: host`: it suppressed every event on the Docker Desktop host
  this was verified on, and it is not required for the modern eBPF probe.

## Limits

- **Detect, not contain.** There is no kill, quarantine, paging or SIEM
  integration in this repository.
- **Docker Desktop is not the reference environment.** The syscall rules fire,
  but `/proc` metadata (`proc.cmdline`, `proc.pname`) can be unavailable, so the
  data-container entrypoint and healthcheck exceptions are effective on a
  native Linux host only. The container is noisy at healthcheck cadence on
  Docker Desktop.
- **`/tmp` is scratch.** The worker rule does not alert on a write under `/tmp`
  outside `TOOL_WORKSPACE_ROOT`; the tool layer remains the primary control.
- **No rotation.** `artifacts/falco/events.json` grows until the operator rotates
  it, and a host-root attacker can stop or reconfigure the detector.
- **Not in CI.** CI is unprivileged, so the compose contract, rules and allowlist
  are tested there; the live triggers are the smoke script on a host with the
  Falco image.

## Related

- [ADR-017](../../docs/adr/ADR-017.md) — decision record, privilege model, residual risk.
- [`ALLOWLIST.md`](ALLOWLIST.md) — reviewed baseline exceptions.
- [`scripts/falco_smoke.sh`](../../scripts/falco_smoke.sh) — deterministic triggers and negative cases.
- [`tests/test_falco.py`](../../tests/test_falco.py) — compose contract, rule invariants and allowlist dates.
- [ADR-016](../../docs/adr/ADR-016.md) — build-time image scan and SBOM.
