### IDEA-019: Scan container images and publish an SBOM with Trivy

- status: done
- priority: P2
- phase: v0.2
- area: security
- tags: supply-chain, docker, sbom, ci, compliance
- depends-on: -
- spec: -
- created: 2026-11-11
- updated: 2026-11-11
- source: review of COMPLIANCE.md SOC 2 CC7.2, SECURITY.md §Vulnerability Management and THREAT_MODEL.md T11 against .github/workflows/ci.yml and docker-compose.yml, 2026-11-11

**Problem**

The only supply-chain gate is a Python-dependency audit. The `supply-chain`
job (`.github/workflows/ci.yml:221-248`) installs the locked environment and runs
`scripts/update_threat_intel.py` at line 240, which queries OSV for every package
in `uv.lock` and exits non-zero on an unignored advisory. That covers the wheels
in the venv and nothing else: OS layers, base images and the shipped runtime are
invisible to it. `docker-compose.yml` references nine images — the locally built
`bastion-agent:${BASTION_IMAGE_TAG:-local}` from the repo `Dockerfile`, plus
`postgres:16-alpine@sha256:aa6cb33c…`, `dpage/pgadmin4:9.19` (profile
`pgadmin`), `redis:7-alpine@sha256:c5d34a98…`, `redis/redisinsight:3.8` (profile
`redis-ui`), `quay.io/keycloak/keycloak:26.0@sha256:09a381c7…`,
`${OMNIROUTE_IMAGE:-rigging/omniroute:3.8.52}`,
`${LLAMA_CPP_IMAGE:-ghcr.io/ggml-org/llama.cpp:server-cuda@sha256:f2880315…}`
and `otel/opentelemetry-collector-contrib:0.111.0@sha256:a2a52e43…` — and none
of them is scanned. There is no SBOM, no `trivy.yaml`, no image, IaC or secret
scan in any workflow, and no artifact that records what was shipped.

The documents disagree with the tree in both directions. `COMPLIANCE.md:103`
marks SOC 2 CC7.2 ✅ Implemented citing "vulnerability scanning, SBOM
generation", and `SECURITY.md:267-269` claims "Weekly Snyk scans" and an SBOM
"generated per release" — yet no Snyk, CodeQL, gitleaks or cosign step, config or
dependency exists anywhere in the repository, and no SBOM file is written to
`artifacts/` (which holds only `evals/latest.json`, `gate/<timestamp>/` and
`threat-intel/latest.json`). `THREAT_MODEL.md` T11 is the honest record —
`PARTIAL` for OSV, `PLANNED` for "SBOM generation, image pinning and signing" —
except that line 249 says the OSV script "is not run in CI" and line 250 still
lists "a CI gate on the OSV script" as planned while `ci.yml:240` runs it on
every push, and §7 gap 6 repeats the same stale ask. So the compliance documents
overclaim a control and the one accurate document still understates the gate
that exists.

**Outcome**

One documented command turns the shipped image set into evidence:
`docker compose --profile compliance run --rm trivy-scan` (or the exact
equivalent recorded in the ADR) writes a CycloneDX SBOM and a CVE report per run
under `artifacts/compliance/<date>/`, exits non-zero on an unignored CRITICAL,
and the CI `supply-chain` job uploads the same artifacts and fails the build on
the same rule. Coverage is derived from `docker compose config --images`, so a
new `image:` line cannot be added without being scanned, and the optional profile
side cars count as shipped images. The scanner never mounts
`/var/run/docker.sock` — a socket is host root and contradicts the
`cap_drop: ALL` baseline every service already carries (`docker-compose.yml`
lines 114-117, 217-219, 282-284) — so it runs with `no-new-privileges`,
`cap_drop: ALL` and a digest-pinned Trivy image. `COMPLIANCE.md`, `SECURITY.md`
and `THREAT_MODEL.md` T11 state one status for the control and point at the job,
the command and the artifact that prove it, and the new component and its
no-socket rule are recorded in an ADR.

**Acceptance**

- [x] `scripts/scan_images.sh` (the documented command; it wraps `docker compose --profile compliance run --rm trivy-scan`) writes `artifacts/compliance/<date>/sbom.cdx.json` and `cve.json` for a clean scan and exits 0, and exits non-zero on an unignored CRITICAL; `uv run pytest tests/test_compliance_scan.py -q` feeds one CRITICAL and one ignored CRITICAL through the same gate
- [x] Coverage is derived from the file: `scripts/image_inventory.py` enumerates the nine `image:` references, including the `pgadmin` and `redis-ui` profile images and the locally built `bastion-agent`; a test adds a new `image:` to a compose fixture and asserts the scan list grows
- [x] `supply-chain` scans images after the OSV audit, uploads `artifacts/compliance/` as `compliance-reports` with a SHA-pinned `actions/upload-artifact`, fails on an unignored CRITICAL, and `ci-ok` still requires `supply-chain`
- [x] `trivy.yaml` is the only suppression path and is read by the gate, not by Trivy: every entry carries the Trivy id, the image scope, a justification and an expiry; an unexpired match suppresses, an expired entry fails even when unused, proven by `tests/test_compliance_scan.py`
- [x] `grep -n "docker.sock" docker-compose.yml` returns nothing; `trivy-scan` declares `cap_drop: [ALL]`, `no-new-privileges:true`, no `privileged`, no ports, and the Trivy image is pinned by digest; the tarball mechanism is stated in a compose comment and ADR-016
- [x] `artifacts/compliance/*` is ignored with a tracked `artifacts/compliance/.gitkeep`, mirroring the `artifacts/gate/*` block in `.gitignore`
- [x] `COMPLIANCE.md` CC7.2 names the job, command and artifact path; `SECURITY.md` §Vulnerability Management states what runs, on what triggers, and where the SBOM is written; "Weekly Snyk scans" is gone
- [x] `THREAT_MODEL.md` T11 marks the OSV audit and the image scan LIVE, drops the stale "not run in CI" sentence, names the remaining gaps, and §7 gap 6 is updated
- [x] `docs/adr/ADR-016.md` records the scanner, the transport, the gate and the artifact layout, is indexed, and `check_adrs.py` passes
- [x] `scripts/gate.sh` passes 10/10 (`pytest` 588 passed, `ruff`, `mypy`, `pylint`, `check_adrs`, `check_backlog`, tool catalog, RBAC, DREAD), and `docker compose config` without the profile is unchanged

**Notes**

- Deduplication: no backlog item and no ADR mentions an SBOM, Trivy, image scanning or a supply-chain gate. Grepped `BACKLOG.md` and `docs/adr/` for `SBOM`, `trivy`, `CycloneDX`, `supply-chain`, `cosign`, `Snyk`, `Falco`, `secrets`: the only hits are the documents cited in **Problem** and `SECURITY.md`'s Vault/Falco prose. IDEA-004 (audit export for retention) is the only other item tagged `compliance` and is a ledger concern; IDEA-009 (done) authored the observability ADR for a pipeline that already existed, a different gap; IDEA-010 (ADR-006 drift) and IDEA-011 (done, rate-limit drift) are the same genre of doc reconciliation but different controls. `spec: -` is deliberate: no Accepted ADR governs supply-chain scanning, so the item authors the decision (ADR-016) instead of citing one, and `THREAT_MODEL.md` T11 only records status, not a decision.
- Classification: `P2`/`v0.2`. The doc overclaim is a current-phase defect (COMPLIANCE.md asserts a SOC 2 control with no evidence today, and v0.2 is "Hardening"), so the conservative home is the current phase; the build is a gate addition rather than product capability, which is why this is not `P1` (no stated security invariant is broken and the stack runs). `area: security` because the load-bearing content is a cross-cutting supply-chain invariant plus the truthfulness of a stated control, spanning compose, CI and three documents; `infra` is the mechanical alternative because most edited lines land in `docker-compose.yml` and `.github/workflows/ci.yml`. Triage may split this into "correct the docs now" (docs, v0.2) and "build the gate" (security/infra, v0.5 "compliance mode", the only phase line whose scope touches compliance evidence) — the acceptance is written so both halves are separable.
- Chosen image-access mechanism, to be confirmed against Trivy's current docs before coding: `docker save <image> | docker run -i … trivy image --input -` (the tarball arrives on stdin, so the scanner needs no socket, no registry credentials and no privileges), with the `trivy` server in the `compliance` profile holding the vulnerability DB so repeated runs do not re-download it. Rejected: a `/var/run/docker.sock` mount (host root, and inconsistent with the `cap_drop: ALL` baseline), and a throwaway local registry (extra service, writable volume and port for no security gain). The alternative to weigh before committing is scanning registry-hosted images by reference and using the tarball only for `bastion-agent`: faster, but the scanner then needs egress to five registries and the SBOM is no longer built from the bytes actually running. Whichever wins, the ADR records it with this trade-off, and `docker save` cost on the CUDA `llama-cpp` image (multiple GB) is the number that decides.
- Deliberately out of scope, each a follow-up item rather than bundled work: runtime detection (Falco or equivalent), secrets management (OpenBao/Vault) — `SECURITY.md` and `THREAT_MODEL.md` T4/T6 already name it as a production prerequisite, audit-log WORM export / head-hash anchoring (T10), and image signing plus signature verification (cosign, T11). Also out: pinning the three tag-only images (`pgadmin4:9.19`, `redisinsight:3.8`, `omniroute:3.8.52`) to digests — that is a compose-only change with its own blast radius on upgrade procedure, and this item should report them as findings rather than silently pin them. IaC scanning of `config/keycloak/realm-export.json` and secret scanning of the tree are separate gates with separate false-positive budgets.
- Why the docs matter enough to be in scope: a reviewer or auditor reading `COMPLIANCE.md:103` is told CC7.2 is implemented; `THREAT_MODEL.md:9` explicitly says that document is not a compliance attestation, but `COMPLIANCE.md` makes no such disclaimer for its ✅ column. Either the evidence exists or the row must say planned — leaving the ✅ while adding a scanner elsewhere would still be an unsupported claim until the artifact path is named.
- Open questions for triage: whether the scan runs on every push or nightly (the CUDA image makes a full nine-image scan expensive on a hosted runner), whether `pgadmin` and `redisinsight` are scanned in CI although their profiles are never started there, whether the ignore file lives at `trivy.yaml` (repo root, CLI default) or under `config/compliance/`, and whether a drifted low-severity finding should warn or fail.
- Intake only: no implementation, no compose, CI, `trivy.yaml`, `.gitignore`, doc or ADR edit is part of this capture.

- Implementation (2026-11-11), deviations recorded rather than hidden:
  - Transport is a tarball, not server mode. `trivy image --input` is a client-side path and server mode scans an image reference, so a server would have re-downloaded the images and stopped the SBOM from describing the bytes on disk. A shared `trivy_cache` volume holds the vulnerability DB instead, so repeated runs do not re-download it. The Outcome's "exact equivalent recorded in the ADR" covers the entry point: `scripts/scan_images.sh` wraps `docker compose --profile compliance run --rm trivy-scan`.
  - Inventory parses `docker-compose.yml` instead of calling `docker compose config --images`: rendering the file requires nine `${VAR:?}` secrets and CI has no `.env`. The parser expands `${VAR:-default}`, fails closed on an unset required variable, and a test pins both behaviours.
  - The scanner is `ghcr.io/aquasecurity/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c` (manifest-list digest) because Docker Hub denied the anonymous pull from this host.
  - CI scans on every push as the acceptance requires; the CUDA image makes the worst case a ~45-minute job. Moving the image half to a nightly run is a change to ADR-016, not a silent workflow edit.
  - Two live-run fixes are in the script: `docker save` writes `0600` under the development umask, and the scanner has no `DAC_OVERRIDE` because of `cap_drop: ALL`, so tarballs are chmod 0644 and the reports directory is a 0777 scratch path under `artifacts/`.
  - Live verification: the documented command scanned `alpine:3.20`, produced a 15-component CycloneDX SBOM and 0 CRITICAL, and exited 0; the failing path is covered by `tests/test_compliance_scan.py` (16 tests). The inventory reads the project `.env` like Compose (process environment wins over the file), and `--no-env-file` keeps the file's defaults reproducible so a developer override such as `LLAMA_CPP_IMAGE` cannot make the suite environment-dependent.
