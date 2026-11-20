#!/usr/bin/env python3
"""The harness the walkthrough scripts share (IDEA-082).

Each ``scripts/demo_*.py`` keeps its scenarios, sample data and its own
arguments, and exposes one entry point — ``main(argv: list[str] | None = None)
-> int``. Everything they used to repeat lives here: the ``--help`` description
that must survive ``python -OO``, the parser skeleton, the Redis/vault/sanitizer
stack closed once in a ``finally``, the ``PASS``/``FAIL`` footer and the three
exit codes a demo may end with.

The demos narrate their own stages; this module only owns what is common, so a
transcript in ``DEMO.md`` changes in one place or not at all.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Final

from agent.dlp.vault import TokenVault, get_vault
from agent.egress.sanitizer import EgressSanitizer
from db.redis import close_redis, get_redis
from settings import Settings

#: Every walkthrough runs in its own tenant with TTLs short enough that a
#: crashed demo leaves nothing behind for long (ADR-012).
DEMO_TENANT: Final[str] = "demo"
DEMO_CANARY_TTL: Final[int] = 120
DEMO_TRIP_TTL: Final[int] = 30

EXIT_PASS: Final[int] = 0
EXIT_INVARIANT: Final[int] = 1
EXIT_UNAVAILABLE: Final[int] = 2


class DemoFailure(RuntimeError):
    """A demo invariant did not hold."""


def check(condition: bool, message: str) -> None:
    """Fail the demo loudly instead of printing a misleading success."""
    if not condition:
        raise DemoFailure(message)


def parser(doc: str | None, fallback: str) -> argparse.ArgumentParser:
    """The parser skeleton: a one-line description, literal under ``python -OO``."""
    description = (doc or fallback).splitlines()[0]
    return argparse.ArgumentParser(description=description)


def verdict(message: str) -> None:
    """The evidence footer of a passing scenario."""
    print(f"\nPASS: {message}")


def redis_unavailable(exc: BaseException) -> None:
    """Exit-2 report shared by every demo that needs the dev Redis."""
    print(f"Redis unavailable: {exc}", file=sys.stderr)
    print("Start the stack with: docker compose up -d redis", file=sys.stderr)


@dataclass(frozen=True, slots=True)
class EgressStack:
    """The real vault and sanitizer a canary demo narrates against."""

    vault: TokenVault
    sanitizer: EgressSanitizer


@asynccontextmanager
async def egress_stack(settings: Settings) -> AsyncIterator[EgressStack]:
    """Build the Redis client, vault and sanitizer, and close Redis once."""
    redis = get_redis(settings.redis_url)
    vault = get_vault()
    sanitizer = EgressSanitizer(
        vault,
        redis,
        canary_prefix=settings.canary_prefix,
        canary_ttl_seconds=DEMO_CANARY_TTL,
        trip_ttl_seconds=DEMO_TRIP_TTL,
    )
    # The sanitizer logs a trip as a WARNING; the demo narrates it itself, so
    # keep the raw log lines out of the transcript.
    logging.getLogger("agent.egress.sanitizer").setLevel(logging.ERROR)
    try:
        yield EgressStack(vault=vault, sanitizer=sanitizer)
    finally:
        await close_redis()


async def run_scenario(
    scenario: Callable[[], Awaitable[None]],
    *,
    unavailable: Mapping[type[BaseException], Callable[[BaseException], None]] | None = None,
) -> int:
    """Run one scenario and turn its failure into the demo's exit code."""
    try:
        await scenario()
    except DemoFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return EXIT_INVARIANT
    except BaseException as exc:
        for kind, report in (unavailable or {}).items():
            if isinstance(exc, kind):
                report(exc)
                return EXIT_UNAVAILABLE
        raise
    return EXIT_PASS


def await_main(coro: Coroutine[Any, Any, int]) -> int:
    """The async runner behind a demo's sync ``main``."""
    return asyncio.run(coro)


def main_guard(main: Callable[[], int], module_name: str) -> None:
    """Run the script when executed as a file, never when imported.

    The guard lives here so the five demos do not each carry an ``if __name__``
    block that ``DEMO.md`` and the tests must both remember.
    """
    if module_name == "__main__":
        raise SystemExit(main())
