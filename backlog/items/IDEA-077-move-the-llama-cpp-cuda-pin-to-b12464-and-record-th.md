### IDEA-077: Move the llama.cpp CUDA pin to b12464 and record the unchanged base-image findings

- status: done
- priority: P2
- phase: v0.5
- area: infra
- tags: supply-chain, cve, docker, gpu
- depends-on: -
- spec: ADR-016
- created: 2026-11-18
- updated: 2026-11-19
- source: operator report in session, measured against ghcr.io on 2026-11-18

**Problem**

`docker-compose.yml:475` pins llama.cpp to `server-cuda@sha256:f2880315…`, the b12211 build created 2026-11-09, while upstream has published b12464 at `sha256:ae96e52f…` (created 2026-11-17, head of both `server-cuda` and `server-cuda-b12464`). Trivy 0.76.1 scans of both digests produce the same 1,019 Ubuntu 24.04 package rows — 0 CRITICAL, 16 HIGH across 4 unique CVEs (gnupg `CVE-2025-68973`, apt `CVE-2026-109518`, openssl `CVE-2026-45447` and `CVE-2026-84782`), 234 unique MEDIUM, 57 unique LOW — because `docker pull` reports nine base layers "Already exists": only the llama.cpp layers differ, so the refresh cannot clear a base-package finding. All four HIGHs have Ubuntu fixed versions, but they need the upstream `nvidia/cuda` base rebuilt, not a llama.cpp tag bump. ADR-016 decision 4 fails only on CRITICAL, so the gate is green and nothing forces either the pin refresh or a disposition for the HIGHs.

**Outcome**

`docker-compose.yml` pins b12464 by digest, the item records the measured before/after so the experiment is not repeated, and the four HIGHs are dispositioned as "fixed upstream, waiting for the base rebuild" (or an accepted risk with a reason) rather than suppressed in `trivy.yaml`. The stack still serves a chat completion from the local model, and no one claims the refresh reduced the findings.

**Acceptance**

- [x] The b12464 scan is recorded in the item next to the b12211 one, with the base-layer overlap that explains the identical counts
- [x] `grep -n "sha256:ae96e52f8b2106ea82bad786ee2d08bb9b0a8c93403df9c27ae1bf065a118089" docker-compose.yml` matches the `llama-cpp` image line, and the floating `server-cuda` tag still resolves to that digest
- [x] `docker compose up -d llama-cpp` reaches healthy and `curl -fsS http://127.0.0.1:8002/health` plus one `/v1/chat/completions` call succeed on the GPU host
- [x] `scripts/scan_images.sh --build-missing` exits 0 on the full set and `scripts/gate.sh` passes; `trivy.yaml` is untouched because no CRITICAL is involved

**Notes**

- This follows IDEA-025, which digest-pinned this image; it is not a second baseline clean-up. `P2`/`v0.5` follows the rubric's "a real gap that can wait one phase": no CRITICAL is present, the gate is green, and nothing is broken. `area: infra` because the deliverable is a compose pin plus a recorded disposition, unlike IDEA-025's cross-cutting work across five images.
- Measurement: both digests were saved with `docker save` and scanned with the gate's own invocation (`trivy image --input <tar> --scanners vuln`), reusing the cache the 2026-11-11 run populated. Rows overcount packages that ship the same CVE; unique counts are 4 HIGH / 234 MEDIUM / 57 LOW for each. The identical result is structural, not a copy/paste error: the pull of b12464 reused every base layer and fetched only three new ones.
- Upstream tags: `server-cuda` and `server-cuda-b12464` both resolve to `sha256:ae96e52f…`; keeping the `server-cuda@sha256:…` shape means the digest stays authoritative if the floating tag moves. Both images have entrypoint `/app/llama-server` and `NVIDIA_REQUIRE_CUDA=cuda>=12.8`, so the compose `command:` and `healthcheck` need no edit. `LLAMA_CPP_IMAGE` in `.env` can still override the pin with a tag-only reference (ADR-016 residual risk).
- Why the findings are survivable: the service runs `cap_drop: ALL`, `no-new-privileges`, exposes one plain-HTTP port on loopback and executes only `/app/llama-server`; apt and gnupg are not invoked, and TLS is terminated outside the container. That is a reason to accept the wait, not a fix, and it should be written down rather than inferred.
- Cost: the image is 4.4 GB, so a local check is one `docker save` plus two Trivy analyses. CI does not run the scan on a pin-only PR (ADR-016 decision 5, dev-mode cadence), so the evidence is the local run and the next `master` scan.
- Open questions for triage: whether the base-rebuild wait belongs in ADR-016's residual risk or in the item alone; and whether a dated pin-refresh cadence belongs in ADR-016 at all, since currently only a human noticing an upstream build drives it and only CRITICAL can fail the gate.
- b12464 measurement (2026-11-19, `scripts/scan_images.sh --build-missing` with `LLAMA_CPP_IMAGE` set to the pin): 0 CRITICAL, 16 HIGH rows over the same four CVEs (gnupg `CVE-2025-68973`, apt `CVE-2026-109518`, openssl `CVE-2026-45447`, `CVE-2026-84782`), 875 MEDIUM rows / 238 unique, 135 LOW rows / 59 unique. The HIGH set is unchanged from b12211; MEDIUM and LOW moved by four and two unique CVEs only because the Trivy database advanced since the 2026-11-18 measurement. The two images share 10 of their 13 filesystem layers, so only the three llama.cpp layers differ and every base package (and its finding) is byte-identical: a tag bump cannot clear a base-package finding, only an upstream `nvidia/cuda` rebuild can.
- Disposition (2026-11-19): the four HIGHs are accepted as "fixed upstream, waiting for the base rebuild", not suppressed; `trivy.yaml` is untouched because ADR-016 decision 4 fails only on CRITICAL. The wait is acceptable for the reasons already recorded above (no capabilities, one loopback HTTP port, only `/app/llama-server`, no apt or gnupg, TLS outside the container) — a reason to wait, not a fix.
- Verification (2026-11-19): `scripts/scan_images.sh --build-missing` exited 0 on the full twelve-image inventory with the pin in place, and `scripts/gate.sh` reported `14/14 passed`; `trivy.yaml` is unchanged. `docker buildx imagetools inspect ghcr.io/ggml-org/llama.cpp:server-cuda` still resolves the floating tag to `sha256:ae96e52f…`. The pinned image was served in an isolated compose project (separate project name, port 18002, the gitignored model hardlinked into this worktree's `models/`) because the shared `bastion-agent` project belongs to the concurrent IDEA-078 worktree; it reached healthy, `/health` returned `{"status":"ok"}`, and one `/v1/chat/completions` call answered with `system_fingerprint: b12464-d3c3e242c`.
