### IDEA-089: Watch container health for known failure signatures and forward them to Uptime Kuma and ntfy

- status: ready
- priority: P2
- phase: v0.5
- area: infra
- tags: monitoring, availability, docker, minio, uptime
- depends-on: IDEA-039
- spec: ADR-025
- created: 2026-11-19
- updated: 2026-11-19
- source: operator report in session on 2026-11-19, after the MinIO drive went offline while its container healthcheck stayed green

**Problem**

IDEA-039 gave the stack Uptime Kuma monitors for the seven endpoints a client would probe, but it left out the compliance-profile services and, more importantly, there is no record of a container being *unhealthy in a way its Compose healthcheck does not see*. On 2026-11-19 `bastion-minio` reported `healthy` for minutes while `http://127.0.0.1:9000/minio/health/live` reset every connection and its log repeated `taking drive /data offline` and `no online disks found`; the only thing that noticed was `tests/test_audit_witness.py` failing, and only because the stack happened to be up. Nothing logged the transition, so the failure was invisible until a test tripped over it. MinIO has no monitor in `config/uptime-kuma/monitors.json`, and no event from the containers reaches the monitor sidecar or a person.

**Outcome**

A recurring health check for the essential containers probes a known failure signature per service (MinIO's `/minio/health/live` on `:9000` and its drive-offline log line are the first two) rather than trusting the Compose healthcheck alone; every transition is logged as one structured line naming the service, the check and the observed state; and the signal is exposed to Uptime Kuma (a Push monitor or an equivalent event) so Kuma can notify ntfy. Notification credentials come from `.env` and are never committed, the default stack and its healthchecks are unchanged, and the monitors stay socket-free per ADR-025.

**Acceptance**

- [ ] A check exists for MinIO that goes DOWN on the observed failure (port 9000 resetting while the container says `healthy`), not only when the container stops
- [ ] Each transition writes one structured log line with the service, the check and the state; a recorded run of the MinIO failure shows the line
- [ ] Uptime Kuma can consume the signal (push monitor or equivalent) and forward it to ntfy through a notification configured from `.env`, with no credential committed
- [ ] The default stack is unchanged (`docker compose config` without a new profile touches no default service), the monitor still mounts no Docker socket, and the docs state what is watched, what is not, and that a same-host monitor cannot report its own host failing
- [ ] `scripts/gate.sh` passes

**Notes**

- Deduplication: IDEA-039 (done, ADR-025) built the Uptime Kuma sidecar and the seven endpoint monitors, including the status page; this item adds the failure *signature* checks it did not have, the MinIO coverage it omitted, and the ntfy forwarding path. IDEA-022 is Falco runtime process detection, IDEA-019/025 are image scanning. No existing item covers container-internal failure signatures or notification routing.
- Observed evidence: `docker inspect bastion-minio` showed `Status: healthy` throughout; `curl http://127.0.0.1:9000/minio/health/live` returned 56/000; the container log carried `Error: node(127.0.0.1:9000): taking drive /data offline: unable to write+read for 31.489s` and `Failure in periodic refresh for IAM … no online disks found`; a restart of `bastion-minio` restored HTTP 200 in 6 s. Disk was not full (43 GB free, 21% inodes).
- Design questions for triage: whether the pusher is a host-side script under `scripts/` on a timer, a Compose service in the `infra` profile, or a Kuma-native monitor per endpoint (Kuma has no MinIO monitor, so a HTTP keyword monitor on `/minio/health/live` would catch this one); and whether ntfy is a new profile-gated service or an external endpoint in `.env`. The item does not preselect either.
- The MinIO restart was outside this idea: no code was changed while it was captured, and no monitoring was added in this turn.
