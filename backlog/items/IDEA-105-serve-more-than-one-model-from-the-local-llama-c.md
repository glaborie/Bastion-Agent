### IDEA-105: Serve more than one model from the local llama.cpp backend

- status: inbox
- priority: P2
- phase: v0.6
- area: infra
- tags: routing, gpu, docker, omniroute
- depends-on: -
- spec: ADR-004
- created: 2026-11-22
- updated: 2026-11-22
- source: session; "implement multi model support in llama.cpp"

**Problem**

The local backend is single-model by construction. `docker-compose.yml:477-494` starts `llama-server` with exactly one `--model /models/${LLAMA_MODEL_FILE:-qwen2.5-7b-instruct-q4_k_m.gguf}`, one `--alias`, `--parallel 1`, and `models/` is mounted read-only at `/models`; `config/omniroute/config.yaml:53-59` gives the `local-llama` combo that one target (`llama/qwen2.5-7b-instruct-q4_k_m`), and ADR-004 decision 2 fixes a single local alias while ADR-001 decision 4 pins Qwen 2.5 7B Q4_K_M. Nothing in the stack can address a second local model id, so three items that want one either defer it or leave it open: IDEA-028 excludes "a second local model" from tiering, IDEA-091 leaves open whether its L2 intent check uses the local Qwen or a smaller distilled head, and IDEA-027 leaves the embedding backend undecided. The VRAM constraint is real and measured, not hypothetical: ADR-011 records 6,568 MiB of 8,192 resident with the Q4_K_M model on the RTX 3060 Ti, and its fp32 ONNX sessions peak at 7,834 MiB, so any second resident model has to be sized against roughly nothing.

**Outcome**

`llama.cpp` exposes exactly two model ids at the same time that OmniRoute can address as distinct local targets (for example a small auxiliary model beside the Qwen chat model, or an embeddings model), each reachable through its own alias, and a `CONFIDENTIAL` prompt can still only land on a local alias. Two resident models is the target; hot-swapping a single GGUF is out of scope. The serving mode is a recorded decision: concurrent models, or one process per model, or a `--models-dir` style switch, with the measured VRAM and concurrency cost of the extra model written down; if the card cannot carry both, that answer is recorded instead and the item closes as "stays single-model" with the measurement.

**Acceptance**

- [ ] `docker compose config` is valid and a `/v1/chat/completions` call to each local alias answers from the model that alias names, with `response.model` reporting the model that actually ran
- [ ] `uv run pytest tests/test_routing_client.py -q` still passes unchanged, and a test proves a `CONFIDENTIAL` prompt cannot be routed to any non-local alias now that more than one local target exists
- [ ] The post-load VRAM and the per-model concurrency (`nvidia-smi` plus a two-model load) are measured on this host and recorded in the item or its ADR, including the headroom left for the classifier sessions
- [ ] `docs/adr/ADR-004.md` (alias→model mapping) and the ADR-008 v0.6 scope are updated with the chosen serving mode, `config/omniroute/config.yaml` and `scripts/omniroute_bootstrap.py` reconcile the new local combos without drift, and `scripts/gate.sh` passes

**Notes**

- Scope confirmed by the requester (2026-11-22): exactly two local models served at the same time, no hot-swap. The "swap the single model's GGUF" reading (ADR-008 v0.6 local model hot-swap) is explicitly not this item; do not widen it to N models either.
- Deduplication: grepped `backlog/items/`, `docs/adr/` and the compose/OmniRoute config for `llama.cpp`, `local model`, `second model`, `hot-swap`, `models-dir`, `gpu` and `alias`. IDEA-028 (complexity tiering) explicitly excludes a second local model; IDEA-091 (intent) only leaves the option open; IDEA-027 (semantic cache) leaves the embedding backend open and excludes only llama.cpp KV/prefix caching; IDEA-077 is the image pin; IDEA-099/IDEA-094/IDEA-096 are the `/v1/models` listing surface. No ADR decision covers serving several local models, and ADR-008 v0.6's "local model hot-swap" is adjacent, not the same problem, so this is not a duplicate.
- Open questions for triage: which second model (embeddings for a local cache, a small intent/sentiment head, or a second chat model) and therefore which alias contract; whether it runs in the same `llama-server` process, a sibling compose service on a profile, or `llama-server`'s multi-model directory mode on the pinned b12464 image; and the VRAM budget, since the single 8 GB card is already close to its ceiling with the classifier sessions. `spec: ADR-004` names the record whose alias→model mapping must change; the phase is the nearest textual home and triage may reject it as premature for a single-host demo.
