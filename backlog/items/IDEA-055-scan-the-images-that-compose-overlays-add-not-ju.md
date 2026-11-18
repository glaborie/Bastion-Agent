### IDEA-055: Scan the images that compose overlays add, not just the base file

- status: done
- priority: P2
- phase: v0.3
- area: security
- tags: supply-chain, docker, sbom, ci
- depends-on: -
- spec: ADR-016
- created: 2026-11-14
- updated: 2026-11-18
- source: session review on 2026-11-14 of ADR-016's coverage claim against the three compose overlays

**Problem**

ADR-016 derives the image inventory from one file — decision 1 opens "**Inventory is derived from `docker-compose.yml`**" (`docs/adr/ADR-016.md:17`) and the Consequences say "Coverage follows the compose file, so a new service is scanned or the run fails on an unset variable" (`docs/adr/ADR-016.md:33`) — and the code does exactly that: `scripts/image_inventory.py:34` sets `DEFAULT_COMPOSE = ROOT / "docker-compose.yml"` and `read_images` parses the `image:` lines of that one text file, while `scripts/scan_images.sh:27` sets `COMPOSE_FILE="docker-compose.yml"` and, although it accepts `--compose FILE` (`:12`), nothing in CI or the documented command passes an overlay: `.github/workflows/ci.yml:402` runs `./scripts/scan_images.sh --build-missing` and ADR-016 decision 5 (`:25`) documents that same invocation. Two overlays therefore escape a control whose stated design is that coverage follows the compose file: `docker-compose.pki.yml:24` ships `smallstep/step-ca:0.28.4@sha256:0f88382a...` for the `ca`, `pki-init` and `pki-issue` services through the top-level `x-pki-image` anchor, and the unmerged Vault overlay (branch `vault-secrets-overlay`, commit `ab3b491`) adds `vault` and `vault-bootstrap` from `vault/Dockerfile`, whose `FROM hashicorp/vault:1.17.0` is tag-only; `docker-compose.gpu.yml` adds no image, so the gap is these two files, not a general one. The overlay images are not merely unscanned but unrepresentable: `uv run python scripts/image_inventory.py --compose docker-compose.pki.yml --no-env-file` exits 2 with "no image references found", because the anchor sits at column 0 and `SERVICE_HEADER` matches only two-space service headers, so even `--compose` cannot see an image an overlay declares. Every document that describes the control still claims full coverage — `README.md:78` ("Every image the stack ships is scanned"), `SECURITY.md:278`, `THREAT_MODEL.md:282` and `COMPLIANCE.md:104`, where SOC 2 CC7.2 is marked ✅ Implemented on that basis.

**Outcome**

The inventory renders the union of the base file and every overlay the stack can be started with, so an overlay that adds a service is scanned or fails the run on an unset variable exactly as the base file does today; a `build:`-only overlay service has a defined, documented treatment instead of vanishing. The documented scan command and the `supply-chain` job cover that union, `manifest.json` shows the `step-ca` and Vault references, and fail-closed behaviour still keys off each file's own `${VAR:?}`. `trivy.yaml` remains the only suppression path, so a finding on an overlay-only image is scoped by slug and expires like any other. The Vault image is digest-pinned in the same change, because an image the inventory has just started reporting is what a suppression is scoped to, and the documents that assert coverage describe the set that is actually scanned.

**Acceptance**

- [x] `uv run python scripts/image_inventory.py --compose docker-compose.yml --compose docker-compose.pki.yml --no-env-file` prints the base set unchanged plus `smallstep/step-ca:0.28.4@sha256:0f88382a...`, and the single-file invocation still prints only the base set, so the union is additive per file
- [x] The documented command covers the union with no arguments: `scripts/scan_images.sh` renders base plus every `docker-compose.*.yml` overlay (or takes a repeatable `--compose`), `manifest.json` lists the `step-ca` and Vault references, and `.github/workflows/ci.yml:402` invokes the same form
- [x] Fail-closed holds per file: an overlay declaring `${NAME:?}` that is unset makes the inventory exit 2 naming `NAME`, and `scripts/scan_images.sh` supplies its throwaway render values for every file it renders — its `--required-vars` call (`:59`) currently reads the base only — asserted by a test
- [x] `uv run pytest tests/test_compliance_scan.py -q` gains a fixture overlay that adds one `image:` and one service that inherits a top-level `x-` anchor: the inventory grows by exactly those references, so an anchor-declared overlay image can no longer exit 2 "no image references found" (today's behaviour on `docker-compose.pki.yml`)
- [x] A `build:`-only overlay service has a defined scan behaviour rather than being skipped silently: either the inventory reports the image its Dockerfile produces (the Vault case, `vault/Dockerfile:7`) or ADR-016 records the exclusion and the reason; either way `scripts/scan_images.sh --build-missing` builds it instead of pulling a non-existent registry reference, since the fetch phase special-cases only `bastion-agent:*`
- [x] `./scripts/scan_images.sh --build-missing` exits 0 over the union, or every finding on `step-ca` and the Vault image is a `trivy.yaml` entry with image slug, statement and expiry; a test asserts an overlay-only slug can be suppressed, an absent slug fails, and Trivy is still invoked with no `--ignorefile`
- [x] `docker-compose.vault.yml` and `vault/Dockerfile` reference a digest-pinned Vault base (`hashicorp/vault:1.17.0@sha256:...`), matching the `step-ca` pin, so the new inventory entry is stable enough to scope a suppression to
- [x] The coverage claims are truthful: `docs/adr/ADR-016.md:17` and `:33` name the overlay set and the build-only rule, `README.md:78`, `SECURITY.md:278`, `THREAT_MODEL.md:282` and `COMPLIANCE.md:104` describe what is scanned, and `uv run python scripts/check_adrs.py` and `uv run python scripts/recalculate_dread.py --check` pass
- [x] `uv run pytest -q`, `ruff check .`, `ruff format --check .`, `mypy .`, `pylint`, `check_backlog.py --check`, `validate_tool_catalog.py --check` and `validate_rbac.py` stay green, and `scripts/gate.sh` passes

**Notes**

- Deduplication: grepped `backlog/items/` for `overlay`, `image_inventory`, `step-ca`, `docker-compose.pki`, `docker-compose.vault` and `digest`. IDEA-019 (done) built the control, but its acceptance scopes coverage to "the nine `image:` references" of the base file; IDEA-025 (done) cleared that baseline by running `scripts/scan_images.sh` over `docker-compose.yml` only; IDEA-023 (done) added `docker-compose.pki.yml` and explicitly left image scanning to IDEA-019 as "a different control" (`:96`), without claiming the `step-ca` image enters the inventory, so this is an unowned gap rather than drift on a promise. IDEA-020 (inbox) plans OpenBao for production secrets and owns neither `docker-compose.vault.yml` nor its pinning. No item covers overlay files; nothing was merged.
- Why P2 rather than P1: ADR-016's "a new service is scanned or the run fails on an unset variable" reads like an invariant, and the honest reading is that it is one — a control that silently excludes two shipped images. It is not P1 by the rubric because no stated invariant is broken *today* in the sense of a live exposure: the unscanned images are a PKI side car and a dev-mode Vault, the base scan is green, and the stack runs. Triage may reasonably raise it to P1 and pull it into v0.2 with IDEA-025's baseline work, since the gap is a coverage hole in a merge-blocking gate rather than new capability.
- The Vault digest belongs in this change: the overlay has to be rendered by the inventory before anything can be scoped to it, and `hashicorp/vault:1.17.0` is tag-only and build-only today, so pinning it is the cheapest point at which the new entry becomes suppressible and stable. Splitting it out would leave the inventory reporting an unpinned reference, which is the exact residual risk ADR-016 already names for `OMNIROUTE_IMAGE` and `LLAMA_CPP_IMAGE`.
- The union is not free: ADR-016 decision 1 rejects `docker compose config --images` because rendering needs secret-shaped variables and CI has no `.env`, so whatever renders the union has to do it the way the current parser does (per-file `${VAR:?}` expansion with throwaway values), and compose merge semantics for `<<: *anchor` across files are the part the hand parser does not implement today. That is the design question this item has to settle, and it may be a small `docker compose -f base -f overlay config --images` run inside the existing throwaway-value export instead of extending the regex parser.
- The Vault overlay is unmerged (branch `vault-secrets-overlay`, one commit): this item must not assume it is on `master`. The `pki` overlay is merged, and its `--compose` failure is the executable evidence available today; the Vault half of the acceptance applies once that overlay lands, and the item does not depend on it because the fixture test proves the general rule.
- Scope: intake only. No parser, script, compose, CI, test, document or ADR edit is part of this capture.
- 2026-11-16, implementation: the design question in Notes is settled inside the existing
  parser, not with `docker compose config --images` — that alternative still needs the secret
  environment ADR-016 decision 1 rejects. `image_inventory.py` gained a repeatable `--compose`,
  `<<: *anchor` resolution (the PKI overlay declares `step-ca` that way, which is why the file
  exited 2), and a build-only rule: a service contributes the final `FROM` of the Dockerfile its
  `build:` stanza names. The Vault overlay names one, so `hashicorp/vault` enters the inventory;
  the GPU overlay names only `target:`, so it adds nothing — the base image is already counted.
- 2026-11-16, evidence: `./scripts/scan_images.sh --compose docker-compose.pki.yml --compose
  docker-compose.vault.yml --build-missing` (the two new images; the full union also needs the
  multi-gigabyte CUDA image) reported 19 CRITICAL rows / 8 unique CVEs — 3 on
  `hashicorp-vault-1.17.0`, 6 on `smallstep-step-ca-0.28.4` — and now exits 0 with 19 suppressed.
  `manifest.json` lists both references with the pinned digests.
- 2026-11-16, trivy.yaml: all eight findings have an upstream fix, so each entry names the release
  that carries it and expires 2026-12-16; the expiry is what forces the Vault base bump and the
  step-ca upgrade. The step-ca pin itself is untouched — bumping the internal CA is an ADR-019
  change, not an inventory change.
- 2026-11-16, out of scope: `trivy.yaml` has no entry for a build-only derivative image (only the
  base it starts from), so a layer the Vault Dockerfile adds after `FROM` is unscanned. That is
  recorded in ADR-016's consequences; scanning the built image would need its Compose-generated
  name, which the parser cannot derive without `docker compose`.
