### IDEA-082: Give the demo scripts one shared harness

- status: active
- priority: P3
- phase: v0.5
- area: tooling
- tags: scripts, demo, refactor
- depends-on: -
- spec: -
- created: 2026-11-18
- updated: 2026-11-20
- source: refactoring scan of `scripts/demo_*.py`, 2026-11-18

**Problem**

The five walkthrough scripts carry 1,001 lines — `demo_classifier.py` (162), `demo_egress.py` (161), `demo_model_canary.py` (250), `demo_tool_request.py` (158) and `demo_traffic.py` (270) — and a line diff between `demo_egress.py` and `demo_model_canary.py` shows 70 identical lines: the import block, the `DEMO_TENANT`/TTL constants, `DemoFailure` and `check()`, the circuit-open preflight, the `finally` cleanup, all of `main()` (Redis, vault and sanitizer construction, both `except` clauses, `close_redis`, `return 0`) and the `__main__` guard, with two further pairs sharing 14 lines of the same shape. The entry points have also drifted into four signatures: `main(argv: list[str] | None = None)` in `demo_classifier.py`, `main(argv: Sequence[str] | None = None)` in `demo_traffic.py`, `async def main() -> int` in `demo_egress.py` and `demo_model_canary.py`, and an argv-less `main()` over an argv-less `parse_args()` in `demo_tool_request.py`. `DEMO.md` quotes all five between Acts 3 and 8 in four different invocation styles, so the transcripts a reader is told to expect can only be kept in step by hand-editing each script, and nothing in `docs/adr/` decides how these scripts are structured.

**Outcome**

`scripts/_demo.py` owns what the five demos repeat: the `main(argv)` entry point and its `ArgumentParser` skeleton, the async runner (`asyncio.run` plus `SystemExit`), the Redis and vault lifecycle with one `finally` close, the sanitizer-log quieting, the span setup and the evidence footer with its exit codes (`0` pass, `1` invariant failure, `2` Redis, model or worker unavailable). Each `scripts/demo_*.py` keeps only its scenario functions, its sample data and the arguments specific to it, and exposes one consistent `def main(argv: list[str] | None = None) -> int`. Every scenario's printed output and exit code is unchanged — same stage lines, same evidence fields — so `DEMO.md` needs no transcript edit, and `tests/test_demo_traffic.py` keeps importing `TURNS`, `Demo`, `main`, `parse_args`, `render`, `run` and `summarize` from `scripts.demo_traffic`.

**Acceptance**

- [ ] `for s in demo_classifier demo_egress demo_model_canary demo_tool_request demo_traffic; do uv run python scripts/$s.py --help; done` exits 0 for all five, and `uv run python -OO scripts/demo_traffic.py --help` plus `uv run python -OO scripts/demo_tool_request.py --help` still print a usage line instead of raising on `__doc__`
- [ ] `docker compose up -d redis` then `uv run python scripts/demo_egress.py` prints the same five stage lines and exits 0, and `uv run python scripts/demo_tool_request.py --tool execute_file_write --actor-sub "$ALICE_SUB" --role operator --arg path=reports/q1.txt` against redis and a running worker prints the same `ticket`/`expires at`/`session` lines and exits 0; both end with the same verdict footer
- [ ] `grep -rn "class DemoFailure\|def check(\|if __name__" scripts/demo_*.py` returns nothing, and `grep -rn "class DemoFailure" scripts/` matches only `scripts/_demo.py`
- [ ] `uv run pytest tests/test_demo_traffic.py tests/test_script_entry_points.py -q` passes unchanged
- [ ] `uv run --no-sync ruff check .` and `uv run --no-sync pylint scripts` are clean, and `scripts/gate.sh` stays green

**Notes**

- `spec` is `-`: no ADR governs the structure of these scripts. `DEMO.md` is the document that quotes their output and is the thing the refactor must leave unchanged; forcing an ADR reference here would invent a decision nobody has taken.
- Deduplication: IDEA-012 (done, dashboard demo console) lists the same five scripts but owns the browser runner, and its notes explicitly defer a host-side `scripts/run_demo.py` — this item is not that script, it is the harness the five existing ones share. IDEA-034 (done) unified demo ticket construction in `agent/demo/scenarios.py` and `seed_demo_approval.py`, not the demo CLIs. IDEA-006 built `demo_egress.py`; IDEA-043 fixed the `__doc__` fallbacks in all eight scripts, whose behaviour must survive, not be re-opened.
- Blast radius, checked: only `tests/test_demo_traffic.py` imports a demo script, and it monkeypatches `scripts.demo_traffic.run`, so that module's public names stay. `agent/demo/scenarios.py` and `tests/test_dashboard_demo.py` refer to the scripts by path string only, and `agent/demo/scenarios.py` reuses the `demo_model_canary.py` compose defaults, so the constants move together or not at all.
- Measurement correction: the per-file line counts above were verified individually, but their sum is 1,001, not the 1,064 quoted by the scan that produced this item. The 70-line overlap was verified by reading both files rather than by running `diff` (shell was unavailable in this session); the identical block is the imports, constants, `DemoFailure`/`check`, the preflight rejection, the cleanup `finally`, `main()` and the `__main__` guard — roughly 67 non-blank lines plus separator blanks, consistent with the reported count. The entry-point divergence is four signatures, not two: `demo_tool_request.py` is the outlier with an argv-less `main()`/`parse_args()`.
- Classification: `P3` because this is maintainability with no phase commitment — ADR-008's current definition of done names no script structure, so `P1` would overstate it. `v0.5` is the current phase and the rubric's home for a change with no other obvious phase.
- The second end-to-end box uses `demo_tool_request.py` because it needs Redis and a worker but no GPU; on a GPU host `demo_model_canary.py` is the stronger check of the shared footer, since it is one half of the 70-line pair.
- Out of scope and not captured: folding `scripts/seed_demo_approval.py` into the harness. It is a ticketing tool rather than a narrated scenario, so it would need a different shape.
