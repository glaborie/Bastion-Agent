### IDEA-003: Route the ONNX ensemble to GPU to meet the 50 ms classify budget

- status: done
- priority: P1
- phase: v0.2
- area: agent
- tags: onnx, gpu, latency, classifier
- depends-on: -
- spec: ADR-011
- created: 2026-11-09
- updated: 2026-11-11
- source: ADR-011, measured 41-98 ms per classify on CPU

**Problem**

`SensitivityClassifier.classify()` measures 41-98 ms on the CPU-only
host, so the stated sub-50 ms budget is missed and every chat turn pays it.

**Outcome**

With `onnxruntime-gpu` and CUDA visible to `gateway` and `worker`,
the ensemble meets the budget on the golden corpus and still runs on CPU when no
GPU is present.

**Acceptance**

- [x] `onnxruntime-gpu` installed in the image with a CPU fallback path
- [x] A benchmark over `tests/data/goldens.jsonl` reports p95 under 50 ms on GPU
- [x] CPU-only verification still passes `tests/test_classifier_evals.py`
- [x] ADR-011 records the measured numbers and the provider chosen

**Notes**

- ADR-011 had already measured the shipped int8 graphs on CUDA and rejected them (1.4–2× slower; `MatMulInteger` has no CUDA kernel). This item re-opened that decision through the ADR's own condition — a graph with real CUDA kernels — by using the fp32 `onnx/model.onnx` that both pinned repositories ship. The int8 path stays the CPU default; a CUDA session selects the fp32 graphs when `CLASSIFIER_*_MODEL_GPU_PATH` is set.
- The fp32 graph is a second calibration, not a drop-in: on the golden corpus it scores the benign prompt-engineering explainer `unsafe` 0.570 against the int8 graph's 0.364, so the int8 `unsafe = 0.5` would add a benign false positive. The fp32 fp-free range is 0.580–0.900; `CLASSIFIER_SAFETY_UNSAFE_THRESHOLD_GPU=0.6` is the chosen point (model recall 14/22, 0/32 FP; joint gate still 28/32 with the same four documented gaps). Injection (`0.662`) and category (`0.3`) are unchanged because the fp32 sweep reproduces their fp-free ranges. With that operating point, a CUDA session reproduces every asserted label (83 rows, 0 mismatches).
- The GPU deployment is opt-in: `docker-compose.gpu.yml` builds the `runtime-gpu` target (onnxruntime-gpu with cudnn, CPU EP retained) and exposes the device with `gpus: all`; the base compose file and the default provider remain CPU. The GPU image was verified without a device: `CLASSIFIER_EXECUTION_PROVIDER=cpu` runs on the CPU EP, and `auto` logs the missing CUDA library and falls back to the CPU EP.
- Latency: `scripts/benchmark_classifier_goldens.py` over the 83-row corpus, five warm-up passes and 30 timed passes: p50 25.6 ms, p95 40.5 ms, p99 50.3 ms, both sessions `CUDAExecutionProvider`; across runs p95 stayed between 40 and 50 ms. Time to first answer after an idle period can exceed the budget while the GPU clocks ramp, which is why the script warms up before timing. The per-probe fp32 CUDA table is in ADR-011.
- VRAM: with the Q4_K_M model resident the card moved from 6,568 MiB to 7,814 MiB after loading the fp32 sessions and peaked at 7,834 MiB of 8,192 (~1.27 GiB delta, ~358 MiB left). Only one process may open the sessions; the gateway is the only classifier user and the worker only closes the router. Recorded in ADR-011.
- Verification: `uv run pytest -q tests/test_classifier_evals.py` 12 passed (int8 CPU gate); golden-label parity under the fp32 CUDA session 0/83 mismatches; benchmark p95 40.5 ms `within_budget`; full `pytest` 612 passed / 2 skipped (`model_integration`, no `LLAMA_CPP_BASE_URL`); ruff check and format clean, mypy clean (48 files), pylint 10.00/10, and `check_adrs.py`, `validate_tool_catalog.py --check`, `validate_rbac.py`, `recalculate_dread.py --check`, `check_backlog.py --check` all OK; `docker compose config` valid for both the base and the GPU override.
- Files changed: `agent/routing/classifier.py` (provider-aware graph selection, CUDA preload, fp32 operating point), `settings.py` (GPU paths/digests and threshold), `scripts/benchmark_classifier_goldens.py`, `Dockerfile` (`runtime-gpu` stage), `docker-compose.gpu.yml`, `docker-compose.yml`, `.env.example`, `docs/adr/ADR-011.md`, `README.md`, `tests/test_classifier.py`, `tests/test_settings.py`.
