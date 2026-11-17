"""One session-id grammar for the vault and the egress sanitizer (ADR-015).

The two key shapes share a digest, so the limit and the rejection text must come
from one function: a limit that drifts on one side silently changes half the
accepted session population.
"""

# pylint: disable=protected-access  # tests assert the key shapes themselves

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from typing import cast

import pytest
import pytest_asyncio
from fakeredis import FakeAsyncRedis
from redis.asyncio import Redis

from agent.dlp.vault import TokenVault
from agent.egress.sanitizer import EgressSanitizer
from db.redis import session_digest

KEY = b"s" * 32
PREFIX = "BASTION-CANARY-"
ACCEPTED = "s" * 256
REJECTED = "s" * 257
REJECTION = "session_id must be at most 256 characters"


@pytest_asyncio.fixture
async def env() -> AsyncIterator[tuple[TokenVault, EgressSanitizer, FakeAsyncRedis]]:
    redis = FakeAsyncRedis(decode_responses=True)
    vault = TokenVault(redis, key=KEY, ttl_seconds=60)
    sanitizer = EgressSanitizer(
        vault,
        cast(Redis, redis),
        canary_prefix=PREFIX,
        canary_ttl_seconds=60,
        trip_ttl_seconds=60,
    )
    try:
        yield vault, sanitizer, redis
    finally:
        await redis.aclose()


async def test_the_vault_and_the_sanitizer_share_the_session_grammar(
    env: tuple[TokenVault, EgressSanitizer, FakeAsyncRedis],
) -> None:
    vault, sanitizer, _redis = env
    digest = hashlib.sha256(ACCEPTED.encode("utf-8")).hexdigest()
    assert session_digest(ACCEPTED) == digest

    await vault.get_or_create("acme", ACCEPTED, "EMAIL_ADDRESS", "alice@example.com")

    assert vault._keys("acme", ACCEPTED)[0] == f"vault:acme:{digest}"
    assert sanitizer._key("acme", "canary", ACCEPTED) == f"egress:acme:canary:{digest}"

    with pytest.raises(ValueError, match=REJECTION):
        await vault.get_or_create("acme", REJECTED, "EMAIL_ADDRESS", "alice@example.com")
    with pytest.raises(ValueError, match=REJECTION):
        sanitizer._key("acme", "canary", REJECTED)
