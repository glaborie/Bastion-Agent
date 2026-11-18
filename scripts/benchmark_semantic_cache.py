"""Offline benchmark for the semantic completion cache (ADR-024, IDEA-027).

Replays a fixed prompt corpus against the shipped cache and a simulated model,
with the cache on and off, and reports hit rate, model calls avoided and the p95
turn latency for both. Nothing here talks to Redis, OmniRoute or a model: the
point is to compare the two code paths on the same corpus, not to measure the
host.

    uv run python scripts/benchmark_semantic_cache.py
"""

from __future__ import annotations

import asyncio
import statistics
import time
from typing import Final, cast

from redis.asyncio import Redis

from agent.semantic_cache import SemanticCache, TokenSimilarity

#: A plausible local completion; only the relative numbers matter.
MODEL_LATENCY_SECONDS: Final = 0.025
REPEATS_PER_PROMPT: Final = 3
PROMPTS: Final = (
    "how do i reset my password",
    "what does the audit ledger verify",
    "why is my connection refused",
    "how do i rotate the canary",
    "which model serves confidential prompts",
    "how do i export the audit chain",
    "what is the four eyes rule",
    "how do i enable payload escrow",
    "why did my chat request return 413",
    "how do i add a tool to the catalog",
)


class MemoryRedis:
    """The two commands the cache uses, so the benchmark needs no server."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self.values[key] = value
        return True


async def play(cache: SemanticCache | None) -> tuple[int, int, list[float]]:
    """Return hits, model calls and per-turn latency for one corpus pass."""
    hits = 0
    calls = 0
    latencies: list[float] = []
    scope = {"tenant_id": "acme", "alias": "cloud-primary", "label": "PUBLIC"}
    for _ in range(REPEATS_PER_PROMPT):
        for prompt in PROMPTS:
            started = time.perf_counter()
            answer: str | None = None
            if cache is not None:
                answer = await cache.lookup(**scope, prompt=prompt)
            if answer is None:
                calls += 1
                await asyncio.sleep(MODEL_LATENCY_SECONDS)
                answer = f"answer for: {prompt}"
                if cache is not None:
                    await cache.store(**scope, prompt=prompt, answer=answer)
            else:
                hits += 1
            latencies.append(time.perf_counter() - started)
    return hits, calls, latencies


def p95(latencies: list[float]) -> float:
    ordered = sorted(latencies)
    return ordered[max(0, int(len(ordered) * 0.95) - 1)]


def report(label: str, hits: int, calls: int, latencies: list[float]) -> None:
    total = hits + calls
    print(
        f"{label:<10} hits {hits:>3}/{total:<3} ({hits / total:5.1%})  "
        f"calls {calls:>3}  "
        f"p50 {statistics.median(latencies) * 1000:7.2f} ms  "
        f"p95 {p95(latencies) * 1000:7.2f} ms"
    )


async def main() -> None:
    print(
        f"corpus: {len(PROMPTS)} prompts x {REPEATS_PER_PROMPT} repeats, "
        f"{MODEL_LATENCY_SECONDS * 1000:.1f} ms simulated model"
    )
    off = await play(None)
    cache = SemanticCache(
        cast(Redis, MemoryRedis()),
        backend=TokenSimilarity(),
        threshold=0.9,
        ttl_seconds=300,
        max_entries=50,
    )
    on = await play(cache)
    report("off", *off)
    report("on", *on)


if __name__ == "__main__":
    asyncio.run(main())
