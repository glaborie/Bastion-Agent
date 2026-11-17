### IDEA-064: Fetch the ONNX guard models as a stack dependency so the gateway can start

- status: ready
- priority: P1
- phase: v0.4
- area: infra
- tags: docker, classifier, models, onnx, dependency, compose
- depends-on: -
- spec: ADR-011
- created: 2026-11-17
- updated: 2026-11-17
- source: incident on 2026-11-17; the gateway container aborted with `ClassifierConfigurationError: injection-guard model not found: models/prompt-injection-guard-small/onnx/model_quantized.onnx`

**Problem**

`docker-compose.yml` mounts `./models` into the gateway and worker read-only and
`ADR-011` derives both graph paths from settings, but nothing in the stack
creates those files. `models/` is gitignored and holds only the GGUF the
`llama-cpp` service needs, so a checkout that has never run the Hugging Face
download documented in `.env` starts the gateway into an immediate
`ClassifierConfigurationError: injection-guard model not found:
models/prompt-injection-guard-small/onnx/model_quantized.onnx`. The documented
manual step is a two-command `uvx hf download` block in `.env` comments, which is
not part of `docker compose up` and is easy to miss; the incident that produced
this item is exactly that miss.

`Settings` defaults `classifier_injection_model_path` and
`classifier_safety_model_path` to those repo-relative paths, so an operator who
did not blank them gets a container that fails closed — correctly, but with a
stack trace instead of a dependency step. CI hides the gap because the eval job
downloads the two repositories and verifies their digests before anything runs.

**Outcome**

The stack materialises the two ONNX repositories itself, verified against the
pinned digests, before the gateway and worker start. A one-shot `models-init`
service runs the fetcher in the application image with `./models` mounted
writable, skips a graph whose file already matches its digest, and fails the
`up` with a named file and digest when the download is unavailable or corrupt;
`gateway` and `worker` depend on it with
`condition: service_completed_successfully`. The fetcher is the same code path
CI uses in spirit — pinned repository, pinned revision, pinned SHA-256 — and
`make models` runs it on the host for tests that need the graphs. The manual
`hf download` block in `.env.example` is replaced by a pointer to the service so
the two cannot drift.

**Acceptance**

- [ ] `uv run pytest tests/test_fetch_models.py -q` passes: a file matching its
      digest is kept without a request, a mismatched digest fails naming the path
      and both hashes, a missing file is fetched from the pinned URL and verified,
      and a failed fetch leaves no partial file under the model directory
- [ ] `make models` materialises both graphs and `uv run python scripts/fetch_models.py`
      exits 0 on the second run without downloading anything, printing the two
      verified paths
- [ ] `docker-compose.yml` defines a one-shot `models-init` service that runs the
      fetcher with `./models` writable, and `gateway` and `worker` both declare
      `depends_on: models-init: condition: service_completed_successfully`; a test
      parses the compose file and asserts both edges and the fetch command
- [ ] `docker compose up -d` on a checkout whose `models/` lacks the guards starts
      the gateway without `ClassifierConfigurationError`, and the two files are
      present afterwards with their pinned digests
- [ ] The pinned repository and revision in the fetcher match the digests the
      classifier verifies (`CLASSIFIER_INJECTION_MODEL_SHA256`,
      `CLASSIFIER_SAFETY_MODEL_SHA256` in `.env.example`), and a wrong revision
      fails the digest check rather than loading a different graph
- [ ] `.env.example`, `README.md` and `docs/TROUBLESHOOTING.md` describe the
      service, how to refetch after a revision bump, and what the gateway error
      looks like when the fetch fails; `docker compose config -q` stays clean and
      `scripts/gate.sh` passes

**Notes**

- `spec: ADR-011` because decision 6 fixes the graph-paths-from-settings contract
  and the provider rules; this item changes how the files arrive, not where they
  are read from.
- Constraint from the compose comment at the gateway mount: models stay in the
  host `./models` directory and are never baked into the image, so the image
  stays small and a model swap does not require a rebuild. A build-time fetch was
  rejected for that reason.
- The fetcher must not print the Hugging Face token or any digest preimage; it
  reports paths, byte counts and the digest comparison only.
- Scope is the two guard repositories. The GGUF that `llama-cpp` loads is a
  separate, much larger dependency with its own licence and is out of scope.
