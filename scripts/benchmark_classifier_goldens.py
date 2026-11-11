#!/usr/bin/env python3
"""Benchmark the ADR-011 ensemble over the golden corpus.

The 50 ms classify budget is a deployment acceptance criterion, so it is
measured over the same 83 prompts the routing gate uses, not over a hand-picked
sample. The script builds the classifier through ``get_classifier()`` — the
path the gateway takes, including the deterministic rules floor — warms it up,
then times ``classify()`` for every row over repeated rounds.

    uv run python scripts/benchmark_classifier_goldens.py
    uv run python scripts/benchmark_classifier_goldens.py --repeats 10 --json

On a GPU host, run it in the CUDA image variant with the provider set to
``cuda`` (see ``docker-compose.gpu.yml`` and ADR-011). A CUDA session selects
the fp32 graphs when ``CLASSIFIER_*_MODEL_GPU_PATH`` is configured; the int8
graphs are the CPU path. The image does not bake ``scripts/`` or ``tests/``, so
mount them:

    docker build --target runtime-gpu -t bastion-agent:gpu .
    docker run --rm --gpus all --env-file .env \
      -e CLASSIFIER_EXECUTION_PROVIDER=cuda \
      -v "$PWD/models:/app/models:ro" -v "$PWD/scripts:/app/scripts:ro" \
      -v "$PWD/tests:/app/tests:ro" -w /app bastion-agent:gpu \
      python scripts/benchmark_classifier_goldens.py --repeats 30

Exit status is non-zero when p95 exceeds ``--max-p95-ms`` (default 50), so the
budget can gate a change instead of living only in a document. ``--max-p95-ms
0`` reports without enforcing.

Measure on a warm card: the first seconds after an idle period can exceed the
budget while the GPU clocks ramp, so the defaults run five untimed passes over
the corpus before the timed ones.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

from agent.routing.classifier import ClassifierConfigurationError, get_classifier
from settings import get_settings

GOLDENS: Final[Path] = Path("tests/data/goldens.jsonl")
BUDGET_MS: Final[float] = 50.0


@dataclass(frozen=True, slots=True)
class Result:
    """Latency over the corpus, in the shape the JSON output uses."""

    rows: int
    repeats: int
    provider_setting: str
    sessions: list[str]
    classify_p50_ms: float
    classify_p95_ms: float
    classify_p99_ms: float
    classify_max_ms: float
    max_p95_ms: float
    within_budget: bool


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--goldens",
        type=Path,
        default=GOLDENS,
        help="golden corpus to read (JSON lines with a prompt field)",
    )
    parser.add_argument("--repeats", type=int, default=30, help="timed passes over the corpus")
    parser.add_argument("--warmup", type=int, default=5, help="untimed passes over the corpus")
    parser.add_argument(
        "--max-p95-ms",
        type=float,
        default=BUDGET_MS,
        help="fail when p95 exceeds this (0 reports without enforcing)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    return parser.parse_args(argv)


def load_prompts(path: Path) -> list[str]:
    if not path.is_file():
        raise SystemExit(f"golden corpus not found: {path}")
    prompts: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        payload = json.loads(line)
        prompt = payload.get("prompt")
        if not isinstance(prompt, str):
            raise SystemExit(f"{path}:{line_number}: missing prompt")
        prompts.append(prompt)
    if not prompts:
        raise SystemExit(f"{path}: corpus is empty")
    return prompts


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def _session_providers(classifier: Any) -> list[str]:
    providers: list[str] = []
    for guard in (getattr(classifier, "_injection", None), getattr(classifier, "_safety", None)):
        graph = getattr(guard, "_graph", None)
        session = getattr(graph, "_session", None)
        if session is not None:
            providers.append(next(iter(session.get_providers()), "unknown"))
    return providers


def run(args: argparse.Namespace) -> Result:
    if args.repeats <= 0 or args.warmup < 0:
        raise SystemExit("--repeats must be positive and --warmup non-negative")
    if args.max_p95_ms < 0:
        raise SystemExit("--max-p95-ms must be non-negative")

    prompts = load_prompts(args.goldens)
    classifier = get_classifier()
    try:
        classifier.ensemble_scores(prompts[0])
    except ClassifierConfigurationError as exc:
        raise SystemExit(f"the ensemble is not configured: {exc}") from exc

    for _ in range(args.warmup):
        for prompt in prompts:
            classifier.classify(prompt)

    timings: list[float] = []
    for _ in range(args.repeats):
        for prompt in prompts:
            started = time.perf_counter()
            classifier.classify(prompt)
            timings.append((time.perf_counter() - started) * 1000)

    p95 = _percentile(timings, 0.95)
    within_budget = args.max_p95_ms == 0 or p95 <= args.max_p95_ms
    return Result(
        rows=len(prompts),
        repeats=args.repeats,
        provider_setting=get_settings().classifier_execution_provider,
        sessions=_session_providers(classifier),
        classify_p50_ms=round(statistics.median(timings), 2),
        classify_p95_ms=round(p95, 2),
        classify_p99_ms=round(_percentile(timings, 0.99), 2),
        classify_max_ms=round(max(timings), 2),
        max_p95_ms=args.max_p95_ms,
        within_budget=within_budget,
    )


def _print_table(result: Result) -> None:
    print(
        f"rows: {result.rows} | repeats: {result.repeats} | "
        f"provider: {result.provider_setting} | "
        f"sessions: {', '.join(result.sessions) or 'rules-only'}"
    )
    print(
        f"classify p50 {result.classify_p50_ms:6.1f} ms | "
        f"p95 {result.classify_p95_ms:6.1f} ms | "
        f"p99 {result.classify_p99_ms:6.1f} ms | "
        f"max {result.classify_max_ms:6.1f} ms"
    )
    if result.max_p95_ms:
        verdict = "within" if result.within_budget else "OVER"
        print(f"budget: p95 {verdict} {result.max_p95_ms:.0f} ms")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = run(args)
    if args.json:
        print(json.dumps(asdict(result), indent=2))
    else:
        _print_table(result)
    return 0 if result.within_budget else 1


if __name__ == "__main__":
    sys.exit(main())
