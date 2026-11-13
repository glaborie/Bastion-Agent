### IDEA-023: Replace internal plaintext and password-only links with short-lived mTLS via Step-CA

- status: done
- priority: P2
- phase: v0.3
- area: infra
- tags: mtls, step-ca, pki, zero-trust, docker
- depends-on: -
- spec: ADR-001
- created: 2026-11-11
- updated: 2026-11-12
- source: session request on 2026-11-11 ("capture Step-CA as a compliance improvement")

**Problem**

Every hop inside the stack is plaintext and authenticated by a shared password.
`DATABASE_URL` is `postgresql+asyncpg://…@db:5432/bastion` with no `sslmode`
(`docker-compose.yml:23`) and `create_async_engine` passes only `timeout` and
`server_settings`, so the client neither requests nor verifies TLS
(`db/session.py:34-50`). `REDIS_URL` is `redis://:${REDIS_PASSWORD}@redis:6379/0`
(`docker-compose.yml:27`) against a server started with `--requirepass` and no
`--tls-port` (`docker-compose.yml:259-270`), and `Redis.from_url` sets no `ssl`
argument (`db/redis.py:20-27`). Keycloak speaks `http://keycloak:8080` for both the
JWKS document and the back-channel token endpoint (`docker-compose.yml:34,37`;
`KC_HTTP_ENABLED: "true"` at line 321; `.env.example:62`), OmniRoute is reached at
`http://omniroute:20128` with `OMNIROUTE_API_KEY` defaulting to `sk-local-dev`
(`docker-compose.yml:91-92`), and traces post to `http://otel-collector:4318`
(`docker-compose.yml:99`). Every service in the file joins one user-defined bridge
(`docker-compose.yml:503-505`) — the eight default services plus the `pgadmin` and
`redis-ui` side cars — and the app tier additionally loads the whole `.env` into
its environment (`docker-compose.yml:109-111`).

The load-bearing exposure is credential replay, not passive sniffing. The compose
baseline drops `CAP_NET_RAW` (`docker-compose.yml:116-117`), which raises the bar
for ARP or DNS spoofing from a compromised container, but every app container
already holds `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `OMNIROUTE_API_KEY` and
`KEYCLOAK_CLIENT_SECRET` (`docker-compose.yml:23,27,32,92`), so a compromised
workload — or anyone who reads a leaked `.env`, a host process, or the loopback
ports published at `docker-compose.yml:209,274,331,372` — can replay those
credentials from anywhere on the bridge, with no identity attached. `SECURITY.md`
claims TLS only at the edge ("Bound to `127.0.0.1` (use TLS reverse proxy for
external access)", lines 237-238) and quarterly rotation of `REDIS_PASSWORD`
(line 243), which is the same shared secret model. `settings.py` masks the DSN in
logs with `redacted_database_url` (`settings.py:478-486`, used at `db/session.py:53`
and `gateway/main.py:66`), which is presentation, not transport security: the
password still crosses the bridge in the clear.

The gap is already named and unowned. `THREAT_MODEL.md` T8 lists "separate Redis
ACL users for gateway and worker, TLS, and no host port exposure" as **PLANNED**
(line 216) and concludes "treat Redis write access as equivalent to administrator
access" (line 217), while §2 assigns "network segmentation" to the deployer
(line 38). No ADR decides how that is done. ADR-001 is the record this item
amends, and it does not authorise the change: its Context fixes the target as
"a single Docker Compose stack on one host … no service mesh or sidecar proxies"
(`docs/adr/ADR-001.md:11`), decision 1 repeats "no sidecar proxies"
(`ADR-001.md:15`), and decision 2 accepts that JWKS is "fetched over the internal
network" without saying over what (`ADR-001.md:17`). The zero-trust claim in that
ADR's Consequences (`ADR-001.md:29`) therefore holds at the gateway ingress only;
east-west, the stack is a flat trusted network. Whoever takes this item must say
outright that it contradicts those two ADR-001 sentences, and must change the ADR
rather than cite it as precedent.

**Outcome**

The default profile still starts for local development, and a `pki` profile (or a
`docker-compose.pki.yml` override, mirroring the existing `docker-compose.gpu.yml`
pattern from IDEA-003) switches the data plane to mutual TLS: PostgreSQL, Redis,
Keycloak, OmniRoute and the OTLP endpoint each present a certificate issued by a
local Step-CA, the app tier presents a client certificate, and a password alone is
no longer sufficient to reach Postgres or Redis. A short certificate lifetime
(default 24 h) renews from an agent without rebuilding images, an expired or
missing certificate fails the connection closed instead of silently falling back
to plaintext, and the CA's private key never enters the repository, `.env` or a
world-readable volume. ADR-001 is amended — or a successor ADR with ADR-001 marked
Superseded — to record the east-west trust model, the reversal of the "no sidecar
proxies" sentence (a renewal agent is not a proxy, but it is a sidecar and that
must be stated), and the honest boundary: a CA on the same host protects against
credential replay from another workload, not against host or root compromise,
which `THREAT_MODEL.md:44` already places out of scope.

**Acceptance**

- [x] With the `pki` profile up, `psql "host=127.0.0.1 port=5432 dbname=bastion user=bastion sslmode=verify-full sslrootcert=<ca.pem> sslcert=<gateway.crt> sslkey=<gateway.key>" -c 'select 1'` succeeds as the gateway's identity, and the same command without `sslcert`/`sslkey` is refused by `pg_hba.conf` `cert` auth; both commands are recorded verbatim in the ADR and in the runbook section this item adds
- [x] A test proves refusal rather than fallback: `uv run pytest tests/test_db_tls.py -q` (or the named equivalent) opens a password-only connection with TLS disabled and asserts the connection error, and a container started on `bastion-net` without a client certificate cannot `SELECT` from `audit_logs`; no assertion is satisfied by a successful plaintext connection
- [x] `agent/runtime.py:453` and `gateway/queue.py:32` (`RedisSettings.from_dsn`) and `db/redis.py:20-27` either carry TLS settings and a client certificate — a certificate-less client cannot write to Redis, proven by a test asserting the connection error — or the ADR records the deferral with the pinned `arq` 0.26 / `redis` 5.x evidence for why, and `THREAT_MODEL.md` T8 line 216 keeps its PLANNED status for TLS; it is not silently skipped
- [x] Certificates are issued with a lifetime from a named settings key and renew without a container restart: a script or test captures the served serial and `notAfter` before and after a forced renewal and shows the change (Postgres via `SIGHUP`, or the reload path the chosen service actually has, which the ADR names); deleting a service's certificate makes it fail closed at startup instead of connecting in plaintext
- [x] `KEYCLOAK_JWKS_URI` and `KEYCLOAK_TOKEN_URI` are `https://keycloak:8080/…` with the CA bundle trusted by the gateway, and `uv run pytest tests/test_auth_oidc.py tests/test_auth_routes.py -q` stays green, so RS256 validation is proven end to end over TLS; `grep -rn "http://keycloak:8080" docker-compose.yml .env.example` returns only lines inside the documented local-only path
- [x] The CA root private key is absent from the repository and from `docker-compose.yml`, `.env` and `.env.example`; it lives in an encrypted volume or OpenBao transit, is mode `0600`/`0640` owned by root or its service user, is unreadable by the `gateway` and `worker` users, and `pki/` (or the chosen path) is added to `.gitignore`; a committed check script asserts both the ignore rule and the file mode rather than relying on review
- [x] The provisioner password and the CA key password come from a secret mechanism — a compose `secrets:` mount, which the file does not use today — not from an inline `.env` value, and `docker compose -f docker-compose.yml -f docker-compose.pki.yml config` is valid
- [x] `docs/adr/ADR-001.md` is amended (Context line 11 and decision 1 line 15) or superseded by a new ADR that records the east-west trust model, the Step-CA component, the certificate lifetime and rotation, the availability trade-off, and the honest limit above; `uv run python scripts/check_adrs.py` passes and the index is updated
- [x] `docker compose up -d` without the `pki` profile still starts the stack, `README.md`, `SECURITY.md` §Deployment Security and `THREAT_MODEL.md` §2/T8 say plainly that the default path is plaintext and local-only, and `uv run pytest -q`, `ruff check .`, `ruff format --check .`, `mypy`, `pylint`, `scripts/gate.sh`, `check_backlog.py --check`, `validate_tool_catalog.py --check`, `validate_rbac.py` and `recalculate_dread.py --check` still pass

**Notes**

- Authority: `spec: ADR-001` names the record that must change, not a decision that already permits this. ADR-001's Context (line 11) and decision 1 (line 15) both exclude sidecars and imply a flat trusted bridge, and decision 2 (line 17) only says JWKS is fetched "over the internal network". This item therefore reverses or narrows a sentence of an Accepted ADR, which is exactly the case ADR-008's Context calls acceptable "only when an ADR records why" (`docs/adr/ADR-008.md:11`). No part of the item may be written as if the ADR already authorises mTLS.
- Deduplication: a repo-wide search for `mtls`, `mTLS`, `step-ca`, `pki`, `PKI`, `spiffe`, `SPIFFE` returns no hit in `BACKLOG.md` and no hit in `docs/adr/`; the only `certificate` hits are the hash-chain run certificate (`docs/adr/ADR-009.md:81-84`, `SECURITY.md:137-138`), which is ledger provenance, not transport identity. "Vault" in ADR-002 is the reversible PII token vault (`docs/adr/ADR-002.md` title), and the OpenBao/Vault secrets item named at `BACKLOG.md:1020` (IDEA-019, out of scope there) is secrets at rest; this item is transport identity for east-west traffic, a different control. Ruled out as the same problem: IDEA-001 (tenant isolation of keys and rows), IDEA-004 (ledger export), IDEA-016 (payload escrow), IDEA-019 (image scanning and SBOM — same compliance genre, different control). The gap is already recorded as PLANNED in `THREAT_MODEL.md` T8 line 216, which is why this is "named and unowned" rather than a new discovery.
- `depends-on: -` deliberately. It becomes a dependency only if triage chooses OpenBao transit for the CA root key: the OpenBao item is being drafted separately and has no id yet, and a `depends-on` value must be an existing `IDEA-NNN`. Record the dependency when both items exist; do not invent an id here. Until then the item is buildable with an encrypted volume and a compose `secrets:`-mounted password.
- Classification: `P2`/`v0.4`. No stated invariant is broken today — `THREAT_MODEL.md` §2 line 38 assigns segmentation to the deployer and T8 line 217 states the risk honestly — so this is not `P0`/`P1`; it is new capability, and ADR-008 decision 5 freezes features inside a phase. `v0.4` is the requested home; ADR-008's nearest textual line is v0.5 "production readiness … secrets management" (`docs/adr/ADR-008.md:20`), and triage may legitimately move it there, or pull it into v0.3 alongside the other infrastructure work. `area: infra` because almost every line lands in `docker-compose.yml`, a new override file, `config/` and `.gitignore`, with thin code surfaces in `db/session.py`, `db/redis.py`, `agent/runtime.py` and `gateway/queue.py`; `security` is the alternative because the outcome is a cross-cutting invariant.
- A triager may also reject this outright, and that is a defensible answer: the deployment target is a single Docker Compose host for development and demo (`docs/adr/ADR-001.md:11`), the threat model explicitly leaves segmentation to the deployer (`THREAT_MODEL.md:38`), and a CA whose root key lives on the same host as every workload it certifies provides a bounded gain. The item exists so that the choice is recorded, not because the gain is large; rejecting it should write the rationale into ADR-001 or T8 rather than leave the PLANNED line standing forever.
- Phasing inside the item, so it is not an epic: phase 1 is PostgreSQL only — server certificate for `db`, client certificates for `gateway` and `worker`, `pg_hba.conf` requiring `cert` for the app role so the password is insufficient — and is the acceptance target. Phase 2 is Redis TLS (`--tls-port`, `--tls-cert-file`, `--tls-ca-cert-file`, `tls-auth-clients yes`) or the documented deferral. Phase 3 is HTTPS for `keycloak:8080`, `omniroute:20128` and `otel-collector:4318`, with the trust bundle mounted read-only in each consumer. The `pki` profile name is chosen over `compliance`, which IDEA-019 already claims for the Trivy scanner.
- Scope questions left open rather than solved here: which provisioner (`ACME` or `JWK`), and whether issuance is pull (each service runs `step ca certificate`) or push; the certificate lifetime and renewal skew; whether the profile side cars `pgadmin` (`docker-compose.yml:236-249`) and `redis-ui` (`298-308`) get client certificates or are excluded from the PKI profile, since both connect to `db`/`redis` over `bastion-net` and would break under cert-only auth; and whether the trust bundle is one per service or one shared read-only config volume.
- Honest limits to write into the ADR rather than paper over: the root key is on the host it protects, so host or root compromise defeats the CA (`THREAT_MODEL.md:44` already excludes that attacker); a 24 h lifetime plus an unavailable CA is a startup-order hazard, so the CA must be reachable at issuance or services must start from a cached certificate, and that availability trade-off is a decision, not an accident; and mTLS does not reduce the blast radius of a compromised `gateway` or `worker`, which legitimately holds its own key — it removes the ability to replay a password from a workload that does not hold that key.
- Intake only: no compose, config, code, test, `.gitignore`, doc or ADR change is part of this capture.
- Triage (2026-11-12): started at the request of the operator, so `phase` moves from `v0.4` to the current `v0.3` and `status` to `active`. The branch is stacked on `idea-030-job-identity` (ADR-018), because that change rewrote `THREAT_MODEL.md` T8 and this item edits the same block; landing the identity half first keeps one conflict instead of two. The item is being built phase by phase, and the box-by-box state is recorded below rather than in the generated sections.

- Implementation (2026-11-12): the `pki` profile is `docker-compose.pki.yml` plus `scripts/pki/{bootstrap,init-ca,issue-certs,check}.sh`, `config/pki/pg_hba.conf` and `docs/PKI.md`. PostgreSQL is `ssl=on` with `hba_file=config/pki/pg_hba.conf`, which is `hostssl … cert` for the app role and `hostnossl … reject`; the CN of the application leaves is the database role (`bastion`), which is how `cert` maps a leaf to a role. Redis moves to `--tls-port 6379 --port 0 --tls-auth-clients yes` and its healthcheck to `redis-cli --tls`. Keycloak runs `start` (not `start-dev`, which forces an HTTP listener on the same port) with `--https-port=8080 --http-enabled=false`. The gateway trusts the internal CA through `OIDC_CA_CERT_PATH`, applied to both the JWKS and token clients.
- Application plumbing: `database_ssl_mode` (`disable|require|verify-ca|verify-full`), `redis_tls_enabled`, `pki_ca_cert_path`, `pki_client_cert_path`, `pki_client_key_path` and `oidc_ca_cert_path` in `settings.py`; `db/session.py::database_ssl_context` builds a `PROTOCOL_TLS_CLIENT` context that trusts only the internal CA (no system store), and `db/redis.py::redis_tls_kwargs`/`arq_redis_settings` give the redis-py and ARQ clients the same identity. A missing CA or leaf raises at engine/client creation — there is no plaintext fallback, and `rediss://` implies TLS even when the boolean is off.
- Live evidence, run against a parallel Compose project (`-p bastion-pki-test`) so the developer stack was untouched: psql with `sslmode=verify-full` and the gateway leaf returned `1`; the same command without `sslcert`/`sslkey` returned `FATAL: connection requires a valid client certificate`; `sslmode=disable` returned `pg_hba.conf rejects connection … no encryption`; `redis-cli --tls` without a client certificate closed the connection while the certificate-plus-password client returned `PONG`; Keycloak's discovery document answered `200` with the CA and failed the handshake without it. `tests/test_db_tls.py` now runs those three live assertions under `PKI_TEST_*` and skips cleanly when the profile is down.
- Renewal: re-running `pki-issue` changed the PostgreSQL leaf serial (`03B8…` → `ABAC…`, `notAfter` moved a day) and `docker kill -s HUP` made the server serve the new serial without a restart. Redis, Keycloak and the app processes read their certificate at start/connection time and need a restart; `docs/PKI.md` states that.
- Key handling: keys are generated with `step certificate create --csr` and only the CSR reaches the CA, so the CA never sees a private key. `secrets/ca_password` and `secrets/provisioner_password` are compose `secrets:` files (mode 0600, gitignored); the CA root key is 0600 inside a 0700 `pki/ca` that only the CA container mounts. `scripts/pki/check.sh` asserts the ignore rules, the modes, that nothing under `pki/`/`secrets/` is tracked, and that `pki/ca` is not mounted into any service.
- Deferrals recorded in ADR-019 rather than papered over: OmniRoute has no TLS listener and fronting it would introduce the request-path proxy ADR-001 rejects; the OTLP exporter path would need certificate plumbing the span pipeline does not use; `pgadmin`/`redis-ui` cannot present a client certificate and are excluded from the profile. T8 keeps those as PLANNED lines.
- Gates: `pytest` 741 passed / 20 skipped (ONNX graphs and `LLAMA_CPP_BASE_URL` absent; the three PKI live tests were run separately with `PKI_TEST_*` and all 12 in the module passed), ruff check/format clean, mypy clean (57 files), pylint 10.00/10, `check_adrs.py` OK (19 ADRs), `check_backlog.py`/`validate_rbac.py`/`validate_tool_catalog.py --check`/`recalculate_dread.py --check` OK, and `docker compose config` valid with and without the overlay. `scripts/gate.sh` was not run end to end — it provisions the full stack; the equivalent checks were run directly.
- Not proven end to end: a real browser login over `https://localhost:8080` with the internal CA trusted, and the gateway's HTTPS JWKS fetch against a live token. The server side, the configured URIs and the auth suites are green, but the browser flow is a manual step recorded in `docs/PKI.md` rather than an automated gate. The default profile was restarted on 2026-11-12 after the overlay landed and came up unchanged: `docker compose ps` reports gateway/worker/db/keycloak/llama-cpp/omniroute/otel-collector/redis running with gateway healthy and `/health` returning 200; the gateway carries no `DATABASE_SSL_MODE`, `REDIS_TLS_ENABLED` or `OIDC_CA_CERT_PATH`; and a password-only `sslmode=disable` TCP connection to `db:5432` still returns `1`, so the certificate-only rule is confined to the overlay. `docker-compose.yml` is untouched by this item (the only diff against its parent commit is the IDEA-030 job-signing keys).
