"""AES-256-GCM token vault tests (ADR-002)."""

# pylint: disable=protected-access  # tests assert storage invariants

from __future__ import annotations

import asyncio

import pytest
from fakeredis import FakeAsyncRedis

from agent.dlp.vault import TOKEN_PATTERN, TokenVault, VaultDecryptionError
from settings import get_settings

KEY = b"v" * 32


async def test_token_format_and_round_trip() -> None:
    vault, _redis = await _vault()
    token = await vault.get_or_create("session-a", "EMAIL_ADDRESS", "alice@example.com")
    assert token == "{{ENTITY:EMAIL_ADDRESS_1}}"
    assert TOKEN_PATTERN.fullmatch(token)
    assert await vault.get("session-a", token) == "alice@example.com"

    restored = await vault.restore("session-a", f"Contact {token}, or the second on-call engineer.")
    assert restored == "Contact alice@example.com, or the second on-call engineer."


async def _vault() -> tuple[TokenVault, FakeAsyncRedis]:
    redis = FakeAsyncRedis(decode_responses=True)
    return TokenVault(redis, key=KEY, ttl_seconds=60), redis


async def test_repeated_values_reuse_the_same_token() -> None:
    vault, _redis = await _vault()
    first = await vault.get_or_create("s", "EMAIL_ADDRESS", "alice@example.com")
    again = await vault.get_or_create("s", "EMAIL_ADDRESS", "alice@example.com")
    other = await vault.get_or_create("s", "EMAIL_ADDRESS", "bob@example.com")
    assert first == again
    assert other == "{{ENTITY:EMAIL_ADDRESS_2}}"


async def test_different_entity_types_have_independent_counters() -> None:
    vault, _redis = await _vault()
    email = await vault.get_or_create("s", "EMAIL_ADDRESS", "alice@example.com")
    person = await vault.get_or_create("s", "PERSON", "Alice")
    email2 = await vault.get_or_create("s", "EMAIL_ADDRESS", "bob@example.com")
    assert email == "{{ENTITY:EMAIL_ADDRESS_1}}"
    assert person == "{{ENTITY:PERSON_1}}"
    assert email2 == "{{ENTITY:EMAIL_ADDRESS_2}}"


async def test_plaintext_is_never_stored_in_redis() -> None:
    vault, redis = await _vault()
    plaintext = "alice@example.com"
    await vault.get_or_create("s", "EMAIL_ADDRESS", plaintext)
    vault_key = vault._keys("s")[0]
    stored = await redis.hgetall(vault_key)
    assert stored
    assert plaintext not in "".join(stored.values())
    reverse_key = vault._keys("s")[1]
    fields = await redis.hkeys(reverse_key)
    assert fields
    assert all(plaintext not in field for field in fields)


async def test_sessions_are_isolated() -> None:
    vault, _redis = await _vault()
    token = await vault.get_or_create("session-a", "PERSON", "Alice")
    assert await vault.get("session-b", token) is None
    assert await vault.restore("session-b", f"Hello {token}") == f"Hello {token}"


async def test_tampered_ciphertext_is_rejected() -> None:
    vault, redis = await _vault()
    token = await vault.get_or_create("s", "PERSON", "Alice")
    vault_key = vault._keys("s")[0]
    ciphertext = await redis.hget(vault_key, token)
    assert ciphertext
    tampered = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    await redis.hset(vault_key, token, tampered)

    with pytest.raises(VaultDecryptionError):
        await vault.get("s", token)
    with pytest.raises(VaultDecryptionError):
        await vault.restore("s", f"Hello {token}")


async def test_ciphertext_is_bound_to_its_token() -> None:
    vault, redis = await _vault()
    token = await vault.get_or_create("s", "PERSON", "Alice")
    vault_key = vault._keys("s")[0]
    ciphertext = await redis.hget(vault_key, token)
    assert ciphertext
    other = "{{ENTITY:PERSON_99}}"
    await redis.hset(vault_key, other, ciphertext)
    with pytest.raises(VaultDecryptionError):
        await vault.get("s", other)


async def test_ttl_is_applied_and_refreshed_by_restore() -> None:
    vault, redis = await _vault()
    token = await vault.get_or_create("s", "PERSON", "Alice")
    initial = await vault.ttl("s")
    assert 0 < initial <= 60

    vault_key = vault._keys("s")[0]
    await redis.expire(vault_key, 5)
    assert await vault.ttl("s") <= 5
    await vault.restore("s", token)
    assert await vault.ttl("s") > 5


async def test_clear_and_unknown_tokens() -> None:
    vault, _redis = await _vault()
    token = await vault.get_or_create("s", "PERSON", "Alice")
    assert await vault.restore("s", "{{ENTITY:PERSON_99}}") == "{{ENTITY:PERSON_99}}"
    await vault.clear("s")
    assert await vault.get("s", token) is None
    assert await vault.ttl("s") == -2


async def test_concurrent_creation_reuses_one_token() -> None:
    vault, _redis = await _vault()
    tokens = await asyncio.gather(
        *[vault.get_or_create("s", "EMAIL_ADDRESS", "alice@example.com") for _ in range(5)]
    )
    assert len(set(tokens)) == 1
    assert await vault.get("s", tokens[0]) == "alice@example.com"


async def test_invalid_inputs_are_rejected() -> None:
    vault, _redis = await _vault()
    with pytest.raises(ValueError, match="session_id"):
        await vault.get_or_create("", "PERSON", "Alice")
    with pytest.raises(ValueError, match="entity_type"):
        await vault.get_or_create("s", "11PERSON", "Alice")
    with pytest.raises(ValueError, match="non-empty"):
        await vault.get_or_create("s", "PERSON", "")
    with pytest.raises(ValueError, match="32 bytes"):
        TokenVault(FakeAsyncRedis(), key=b"short", ttl_seconds=10)
    with pytest.raises(ValueError, match="TTL"):
        TokenVault(FakeAsyncRedis(), key=KEY, ttl_seconds=0)


def test_settings_provide_a_valid_vault_key() -> None:
    assert len(get_settings().vault_key_bytes) == 32
