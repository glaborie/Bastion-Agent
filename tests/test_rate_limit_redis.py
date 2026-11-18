"""Token-bucket semantics against a live Redis 7 (ADR-013).

``fakeredis`` cannot execute the Lua script without the optional ``lupa``
dependency, so the algorithm is gated here instead of being mimicked in Python.
CI provisions Redis and sets ``REDIS_TEST_URL``; locally the module skips unless
that variable points at a disposable instance:

    docker run --rm -d --name bastion-test-redis -p 56379:6379 redis:7-alpine

    REDIS_TEST_URL=redis://localhost:56379/0 uv run pytest -m redis_integration

Every test uses a random principal id and deletes only its own keys.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from typing import Final

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from gateway.rate_limit import RateLimiter

REDIS_TEST_URL: Final[str] = os.getenv("REDIS_TEST_URL", "")

requires_redis = pytest.mark.skipif(
    not REDIS_TEST_URL,
    reason="REDIS_TEST_URL is not set",
)

pytestmark = [pytest.mark.redis_integration, requires_redis]


def _principal() -> str:
    return f"redis-test-{uuid.uuid4()}"


@pytest_asyncio.fixture
async def limiter() -> AsyncIterator[tuple[RateLimiter, Redis, str]]:
    client = Redis.from_url(REDIS_TEST_URL, decode_responses=True)
    principal = _principal()
    try:
        yield RateLimiter(client), client, principal
    finally:
        await client.delete(
            f"ratelimit:chat:{principal}",
            f"ratelimit:dashboard:{principal}",
            f"ratelimit:chat_tokens:{principal}",
        )
        await client.aclose()


async def test_bucket_allows_exactly_capacity_then_refuses(
    limiter: tuple[RateLimiter, Redis, str],
) -> None:
    bucket, _client, principal = limiter

    decisions = [
        await bucket.consume(principal, "chat", limit=5, window_seconds=60) for _ in range(6)
    ]

    assert [decision.allowed for decision in decisions] == [True] * 5 + [False]
    assert decisions[0].remaining == 4
    assert decisions[-1].remaining == 0
    assert decisions[-1].retry_after_seconds >= 1
    assert decisions[-1].reset_after_seconds >= 1


async def test_principals_and_scopes_do_not_share_a_bucket(
    limiter: tuple[RateLimiter, Redis, str],
) -> None:
    bucket, _client, principal = limiter
    other = _principal()

    for _ in range(3):
        assert (await bucket.consume(principal, "chat", limit=3, window_seconds=60)).allowed
    assert not (await bucket.consume(principal, "chat", limit=3, window_seconds=60)).allowed

    assert (await bucket.consume(other, "chat", limit=3, window_seconds=60)).allowed
    assert (await bucket.consume(principal, "dashboard", limit=3, window_seconds=60)).allowed

    await _client.delete(f"ratelimit:chat:{other}")


async def test_bucket_refills_over_time(limiter: tuple[RateLimiter, Redis, str]) -> None:
    bucket, _client, principal = limiter

    assert (await bucket.consume(principal, "chat", limit=2, window_seconds=1)).allowed
    assert (await bucket.consume(principal, "chat", limit=2, window_seconds=1)).allowed
    assert not (await bucket.consume(principal, "chat", limit=2, window_seconds=1)).allowed

    await asyncio.sleep(1.05)

    assert (await bucket.consume(principal, "chat", limit=2, window_seconds=1)).allowed


async def test_concurrent_requests_cannot_overspend(
    limiter: tuple[RateLimiter, Redis, str],
) -> None:
    bucket, _client, principal = limiter

    decisions = await asyncio.gather(
        *(bucket.consume(principal, "dashboard", limit=10, window_seconds=60) for _ in range(25))
    )

    assert sum(decision.allowed for decision in decisions) == 10


async def test_key_expires_instead_of_leaking(
    limiter: tuple[RateLimiter, Redis, str],
) -> None:
    bucket, client, principal = limiter
    await bucket.consume(principal, "chat", limit=5, window_seconds=60)

    ttl_ms = await client.pttl(f"ratelimit:chat:{principal}")

    assert 0 < ttl_ms <= 60_000


# ---------------------------------------------------------------------------
# Inference token budget (ADR-020)
# ---------------------------------------------------------------------------


async def test_reserve_charges_the_worst_case_and_refuses_above_the_balance(
    limiter: tuple[RateLimiter, Redis, str],
) -> None:
    bucket, _client, principal = limiter

    first = await bucket.reserve(principal, tokens=60, capacity=100, window_seconds=60)
    assert first.allowed
    assert first.remaining == 40

    second = await bucket.reserve(principal, tokens=50, capacity=100, window_seconds=60)
    assert not second.allowed
    assert second.retry_after_seconds >= 1


async def test_settlement_refunds_an_over_reservation(
    limiter: tuple[RateLimiter, Redis, str],
) -> None:
    bucket, _client, principal = limiter
    await bucket.reserve(principal, tokens=80, capacity=100, window_seconds=60)

    # The turn used 20 of the 80 reserved, so 60 comes back.
    balance = await bucket.settle(principal, delta=-60, capacity=100, window_seconds=60)

    assert balance >= 79


async def test_settlement_leaves_debt_and_the_next_turn_is_refused(
    limiter: tuple[RateLimiter, Redis, str],
) -> None:
    bucket, _client, principal = limiter
    await bucket.reserve(principal, tokens=20, capacity=100, window_seconds=60)

    # The provider reported 60: the estimate was 40 tokens short, which becomes
    # debt instead of being refused up front.
    balance = await bucket.settle(principal, delta=40, capacity=100, window_seconds=60)
    assert balance <= 40

    refused = await bucket.reserve(principal, tokens=60, capacity=100, window_seconds=60)
    assert not refused.allowed


async def test_debt_floors_at_negative_capacity(
    limiter: tuple[RateLimiter, Redis, str],
) -> None:
    bucket, _client, principal = limiter
    await bucket.reserve(principal, tokens=5, capacity=10, window_seconds=60)

    # A bogus usage figure cannot empty many windows at once.
    balance = await bucket.settle(principal, delta=10_000, capacity=10, window_seconds=60)

    assert balance == -10


async def test_token_bucket_refills_over_time(
    limiter: tuple[RateLimiter, Redis, str],
) -> None:
    bucket, _client, principal = limiter

    assert (await bucket.reserve(principal, tokens=1, capacity=2, window_seconds=1)).allowed
    assert (await bucket.reserve(principal, tokens=1, capacity=2, window_seconds=1)).allowed
    assert not (await bucket.reserve(principal, tokens=1, capacity=2, window_seconds=1)).allowed

    await asyncio.sleep(0.6)

    assert (await bucket.reserve(principal, tokens=1, capacity=2, window_seconds=1)).allowed
