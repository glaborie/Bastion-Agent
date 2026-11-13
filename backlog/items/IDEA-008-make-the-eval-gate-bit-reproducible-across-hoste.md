### IDEA-008: Make the eval gate bit-reproducible across hosted runners

- status: done
- priority: P1
- phase: v0.2
- area: evals
- tags: ci, onnx, int8, calibration, golden-set
- depends-on: -
- spec: ADR-011
- created: 2026-11-10
- updated: 2026-11-10
- source: CI runs 42866889651, 42870723135 and 42882954274 on 2026-11-10

**Problem**

`Zero-tolerance eval gates (real ONNX models)` is red on `master` for two
consecutive commits even though one of them (`af91390`) only touches
`BACKLOG.md`. Both runs and a re-run land on an AMD EPYC 7763 runner and score
the benign golden rows `CONFIDENTIAL`/`unsafe_content` at 0.75–0.97
(`public-haiku-048` probe: 0.9243); the four documented misses flip to blocked
as well. This is the ADR-011 consequence "the gate's numbers are CPU-dispatch
dependent", now deterministic on that runner image rather than a one-off, so
the recorded mitigation (log the host, the AVX-512 flags and one probe) explains
the failure but does not unblock a merge: a re-run returns to the same image.

The signature is now narrowed to the host's instruction set. Every failing run
landed on an AMD EPYC machine that reports no AVX-512 at all, so `/proc/cpuinfo`
lists no `avx512*` flags and ONNX Runtime selects the AVX2 int8 kernels: EPYC
7763s first, and on the first run of the fix an EPYC 9V74 with the identical
haiku score 0.9243. Every host that reproduced the calibration verdicts has
`avx512_vnni`: Intel Xeon Platinum 8370C, AMD EPYC 9V45, and the calibration
desktop (i7-11700KF). Run 42882954274 (`e5e7c60`, telemetry only) reproduced
0.9243 and both failing tests on a 7763, while the two docs-only commits between
the failures passed on the other hosts. Same wheels, same pinned digests, same
tree: 3 of the previous 8 `master` runs failed and all three were 7763s, so the
verdict is a property of the host rather than of the commit.

**Outcome**

The gate is green on every hosted runner for the same commit, or it fails with
an explicit environment verdict instead of a false "regression". A false
`CONFIDENTIAL` on a haiku stops blocking unrelated changes, and the golden
corpus keeps its zero-tolerance meaning on hosts where the graph is
reproducible.

**Acceptance**

- [x] The eval job either pins a CPU class / container image where the int8 graphs reproduce, or gates the fp32 graph, or records the dispatch anomaly and skips the ratio assertions with a non-green-but-explicit verdict
- [x] `docs/adr/ADR-011.md` records the choice and replaces the "not done" note in Consequences
- [x] A run on the offending AMD EPYC image is reproducible evidence: the probe verdict, the host and the flags appear in the job summary, not only in a log line
- [x] `uv run python scripts/run_evals.py` still exits non-zero on a genuine corpus regression, proven by a deliberately broken golden row in a test
- [x] CI is green on `master` without a manual re-run

**Notes**

- The evidence needed for the fix is already collected by the "Record the
  inference environment" step; what is missing is a decision about what to do
  with it.
- Not caused by the telemetry or demo work in `bb02cf0` / `9bdb5bf`: the same
  failure appears on the docs-only commit that precedes them.
- Resolved in `c7c8616`: `scripts/check_classifier_dispatch.py` classifies five
  golden sentinels and publishes `reference` / `dispatch_anomaly` to the job
  summary and `$GITHUB_OUTPUT`; `agent/routing/dispatch.py` names the anomaly
  only for the systemic signature (every benign sentinel blocked, injection
  still detected); `tests/test_classifier_evals.py` skips the two ratio
  assertions only on that verdict and `scripts/run_evals.py` publishes
  `exempt_gates` instead of a synthetic failure. A failed row is never exempted.
- Live proof, run 42888959001 on an AMD EPYC 9V74 with no AVX-512 flags:
  verdict `dispatch_anomaly`, sentinels `haiku 0.9243`, `weather 0.7990`,
  `translate 0.7526 criminal_planning`, `code-review 0.7848`, injection still
  `0.9997`; `evals: 220/220 passed, 0 failed`, `ClassifierGoldenGate exempt
  (dispatch_anomaly)`, green without a re-run.
