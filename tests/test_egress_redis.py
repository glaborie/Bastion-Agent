"""Quarantine expiry against a real Redis instance (ADR-012 rollout).

The unit suite uses ``fakeredis``, which proves the logic but not the server's
TTL semantics. This module runs the same lifecycle against a live Redis 7:

    docker run --rm -d --name bastion-test-redis -p 56379:6379 redis:7-alpine

    REDIS_TEST_URL=redis://localhost:56379/0 uv run pytest -m redis_integration

It is opt-in because CI does not ship a Redis service. Every test uses a random
session id and deletes only keys under that id, so pointing it at a development
instance cannot erase another subsystem's data.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from collections.abc import AsyncIterator
from typing import Final, cast

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from agent.dlp.vault import TokenVault
from agent.egress.sanitizer import EgressSanitizer

REDIS_TEST_URL: Final[str] = os.getenv("REDIS_TEST_URL", "")
KEY: Final[bytes] = b"r" * 32
PREFIX: Final[str] = "CANARY-"

requires_redis = pytest.mark.skipif(
    not REDIS_TEST_URL,
    reason="REDIS_TEST_URL is not set",
)

pytestmark = [pytest.mark.redis_integration, requires_redis]


def _key(kind: str, session_id: str) -> str:
    """Recompute the sanitizer key space without touching a private method."""
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return f"egress:{kind}:{digest}"


@pytest_asyncio.fixture
async def redis_env() -> AsyncIterator[tuple[EgressSanitizer, TokenVault, Redis, str]]:
    client = Redis.from_url(REDIS_TEST_URL, decode_responses=True)
    session_id = f"redis-test:{uuid.uuid4()}"
    vault = TokenVault(client, key=KEY, ttl_seconds=60)
    sanitizer = EgressSanitizer(
        vault,
        client,
        canary_prefix=PREFIX,
        canary_ttl_seconds=60,
        trip_ttl_seconds=60,
    )
    try:
        await client.ping()
        yield sanitizer, vault, client, session_id
    finally:
        await sanitizer.clear(session_id)
        await client.aclose()


async def test_canary_is_shared_between_replicas_with_the_vault_ttl(
    redis_env: tuple[EgressSanitizer, TokenVault, Redis, str],
) -> None:
    sanitizer, vault, client, session_id = redis_env
    first = await sanitizer.canary_for(session_id)

    # A second worker (separate sanitizer, separate connection) must read the
    # same marker, because the value lives in Redis rather than process memory.
    other = EgressSanitizer(
        vault,
        cast(Redis, client),
        canary_prefix=PREFIX,
        canary_ttl_seconds=60,
        trip_ttl_seconds=60,
    )
    assert await other.canary_for(session_id) == first

    ttl = await client.ttl(_key("canary", session_id))
    assert 0 < ttl <= 60


async def test_concurrent_first_turns_converge_on_one_canary(
    redis_env: tuple[EgressSanitizer, TokenVault, Redis, str],
) -> None:
    sanitizer, _vault, client, session_id = redis_env

    values = await asyncio.gather(
        *(sanitizer.canary_for(session_id) for _ in range(8)),
    )

    assert len(set(values)) == 1
    assert values[0].startswith(PREFIX)
    assert 0 < await client.ttl(_key("canary", session_id)) <= 60


async def test_canary_leak_sets_a_quarantine_key_with_a_ttl(
    redis_env: tuple[EgressSanitizer, TokenVault, Redis, str],
) -> None:
    sanitizer, _vault, client, session_id = redis_env
    canary = await sanitizer.canary_for(session_id)

    result = await sanitizer.inspect(f"Here is the marker: {canary}", session_id)

    assert result.blocked is True
    assert result.reason == "canary_leak"
    assert await client.exists(_key("trip", session_id)) == 1
    ttl = await client.ttl(_key("trip", session_id))
    assert 0 < ttl <= 60
    # The quarantine is shared by every replica, not held in process memory.
    assert await sanitizer.is_tripped(session_id) is True


async def test_quarantine_expires_without_a_cleanup_job(
    redis_env: tuple[EgressSanitizer, TokenVault, Redis, str],
) -> None:
    _sanitizer, vault, client, session_id = redis_env
    fast = EgressSanitizer(
        vault,
        client,
        canary_prefix=PREFIX,
        canary_ttl_seconds=60,
        trip_ttl_seconds=1,
    )

    await fast.trip(session_id, "canary_leak")
    assert await fast.is_tripped(session_id) is True

    # Redis expires the key itself; no sweeper or application timer is involved.
    await asyncio.sleep(1.2)

    assert await fast.is_tripped(session_id) is False
    await fast.ensure_available(session_id)


async def test_clear_removes_only_this_sessions_keys(
    redis_env: tuple[EgressSanitizer, TokenVault, Redis, str],
) -> None:
    sanitizer, _vault, client, session_id = redis_env
    other_session = f"redis-test:{uuid.uuid4()}"
    try:
        await sanitizer.canary_for(session_id)
        await sanitizer.trip(session_id, "canary_leak")
        await sanitizer.canary_for(other_session)

        await sanitizer.clear(session_id)

        assert await client.exists(_key("canary", session_id)) == 0
        assert await client.exists(_key("trip", session_id)) == 0
        assert await client.exists(_key("canary", other_session)) == 1
    finally:
        await sanitizer.clear(other_session)
