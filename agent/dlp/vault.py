"""Reversible, session-scoped token vault backed by Redis (ADR-002).

Detected values are replaced with ``{{ENTITY:TYPE_INDEX}}`` markers. The
plaintext never appears in Redis:

* ``vault:<session-digest>`` holds ``token -> AES-256-GCM(nonce || ciphertext)``;
  the AAD binds the ciphertext to the session id and the token, so a value
  copied into another session/token fails authentication.
* ``vault:<session-digest>:rev`` holds
  ``HMAC-SHA256(vault_key, "vault-index" || type || value) -> token`` so repeated
  values reuse the same marker without storing the value.
* ``vault:<session-digest>:seq`` supplies per-entity counters.

All three keys share the 30-minute TTL, refreshed whenever the session creates
or restores a token. Session ids are hashed before use as Redis keys, so callers
may pass arbitrary identifiers.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import logging
import os
import re
from typing import Any, Final, Protocol, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from redis.asyncio import Redis

from db.redis import get_redis
from settings import get_settings

logger = logging.getLogger(__name__)

#: Markers produced by the DLP engine, e.g. ``{{ENTITY:EMAIL_ADDRESS_2}}``.
TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\{\{ENTITY:([A-Z][A-Z0-9_]{0,31})_(\d{1,9})\}\}"
)
_ENTITY_TYPE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")
_MAX_SESSION_ID_LENGTH: Final[int] = 256
_NONCE_BYTES: Final[int] = 12


class AsyncRedis(Protocol):
    """The small async Redis surface the vault needs (keeps mypy precise)."""

    async def hget(self, name: str, key: str) -> str | None: ...
    async def hsetnx(self, name: str, key: str, value: str) -> bool: ...
    async def hincrby(self, name: str, key: str, amount: int = 1) -> int: ...
    async def hdel(self, name: str, *keys: str) -> int: ...
    def pipeline(self) -> Any: ...
    async def delete(self, *names: str) -> int: ...
    async def ttl(self, name: str) -> int: ...


class VaultError(RuntimeError):
    """Base class for token-vault failures."""


class VaultDecryptionError(VaultError):
    """Ciphertext failed authentication (tampering or wrong session/token)."""


class TokenVault:
    """Encrypt, index and restore session-scoped entity placeholders."""

    def __init__(
        self,
        redis: Redis,
        *,
        key: bytes,
        ttl_seconds: int = 1800,
        prefix: str = "vault:",
    ) -> None:
        if len(key) != 32:
            raise ValueError("vault key must be exactly 32 bytes (AES-256)")
        if ttl_seconds <= 0:
            raise ValueError("vault TTL must be positive")
        self._redis = cast(AsyncRedis, redis)
        self._key = key
        self._ttl = ttl_seconds
        self._prefix = prefix
        self._aes = AESGCM(key)

    # -- public API -------------------------------------------------------
    async def get_or_create(self, session_id: str, entity_type: str, value: str) -> str:
        """Return the stable marker for ``value``, creating it if necessary."""
        self._validate_session(session_id)
        entity = self._validate_entity_type(entity_type)
        if not isinstance(value, str) or not value:
            raise ValueError("entity value must be a non-empty string")

        vault_key, reverse_key, seq_key = self._keys(session_id)
        digest = self._value_digest(entity, value)

        existing = await self._redis.hget(reverse_key, digest)
        if isinstance(existing, str) and existing:
            await self._refresh(vault_key, reverse_key, seq_key)
            return existing

        index = await self._redis.hincrby(seq_key, entity, 1)
        token = f"{{{{ENTITY:{entity}_{index}}}}}"
        ciphertext = self._encrypt(session_id, token, value)

        # Store the ciphertext before publishing the reverse index entry, so a
        # concurrent reader can never resolve a token that has no value yet.
        pipe = self._redis.pipeline()
        pipe.hset(vault_key, token, ciphertext)
        pipe.expire(vault_key, self._ttl)
        await pipe.execute()

        # Concurrency: the first writer wins; a loser adopts the winner's token
        # and removes its own orphaned ciphertext.
        won = await self._redis.hsetnx(reverse_key, digest, token)
        if not won:
            winner = await self._redis.hget(reverse_key, digest)
            if isinstance(winner, str) and winner and winner != token:
                await self._redis.hdel(vault_key, token)
                await self._refresh(vault_key, reverse_key, seq_key)
                return winner
            raise VaultError("reverse index lost a concurrent write")

        await self._refresh(vault_key, reverse_key, seq_key)
        return token

    async def get(self, session_id: str, token: str) -> str | None:
        """Decrypt one marker; ``None`` when the session never created it."""
        self._validate_session(session_id)
        if not TOKEN_PATTERN.fullmatch(token):
            return None
        vault_key, _reverse_key, _seq_key = self._keys(session_id)
        ciphertext = await self._redis.hget(vault_key, token)
        if not isinstance(ciphertext, str):
            return None
        return self._decrypt(session_id, token, ciphertext)

    async def restore(self, session_id: str, text: str) -> str:
        """Replace every known marker in ``text`` with its plaintext."""
        self._validate_session(session_id)
        if not isinstance(text, str) or not text:
            return text
        tokens = {match.group(0) for match in TOKEN_PATTERN.finditer(text)}
        if not tokens:
            return text

        vault_key, reverse_key, seq_key = self._keys(session_id)
        restored: dict[str, str] = {}
        for token in tokens:
            ciphertext = await self._redis.hget(vault_key, token)
            if isinstance(ciphertext, str):
                restored[token] = self._decrypt(session_id, token, ciphertext)
        if not restored:
            return text
        await self._refresh(vault_key, reverse_key, seq_key)
        return TOKEN_PATTERN.sub(lambda match: restored.get(match.group(0), match.group(0)), text)

    async def clear(self, session_id: str) -> None:
        """Delete every mapping for the session immediately."""
        self._validate_session(session_id)
        vault_key, reverse_key, seq_key = self._keys(session_id)
        await self._redis.delete(vault_key, reverse_key, seq_key)

    async def ttl(self, session_id: str) -> int:
        """Remaining lifetime of the session's mappings, in seconds."""
        self._validate_session(session_id)
        vault_key, _reverse_key, _seq_key = self._keys(session_id)
        return int(await self._redis.ttl(vault_key))

    # -- internals --------------------------------------------------------
    def _keys(self, session_id: str) -> tuple[str, str, str]:
        digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        base = f"{self._prefix}{digest}"
        return base, f"{base}:rev", f"{base}:seq"

    def _value_digest(self, entity_type: str, value: str) -> str:
        material = (
            b"vault-index\x00" + entity_type.encode("ascii") + b"\x00" + value.encode("utf-8")
        )
        return hmac.new(self._key, material, hashlib.sha256).hexdigest()

    def _aad(self, session_id: str, token: str) -> bytes:
        return f"{session_id}|{token}".encode()

    def _encrypt(self, session_id: str, token: str, value: str) -> str:
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = self._aes.encrypt(nonce, value.encode("utf-8"), self._aad(session_id, token))
        return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def _decrypt(self, session_id: str, token: str, encoded: str) -> str:
        try:
            payload = base64.urlsafe_b64decode(encoded.encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise VaultDecryptionError("vault ciphertext is not valid base64") from exc
        if len(payload) <= _NONCE_BYTES:
            raise VaultDecryptionError("vault ciphertext is too short")
        nonce, ciphertext = payload[:_NONCE_BYTES], payload[_NONCE_BYTES:]
        try:
            plaintext = self._aes.decrypt(nonce, ciphertext, self._aad(session_id, token))
        except InvalidTag as exc:
            raise VaultDecryptionError(
                "vault ciphertext failed authentication (tampered or wrong session)"
            ) from exc
        return plaintext.decode("utf-8")

    async def _refresh(self, vault_key: str, reverse_key: str, seq_key: str) -> None:
        pipe = self._redis.pipeline()
        pipe.expire(vault_key, self._ttl)
        pipe.expire(reverse_key, self._ttl)
        pipe.expire(seq_key, self._ttl)
        await pipe.execute()

    @staticmethod
    def _validate_session(session_id: str) -> None:
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id must be a non-empty string")
        if len(session_id) > _MAX_SESSION_ID_LENGTH:
            raise ValueError(f"session_id must be at most {_MAX_SESSION_ID_LENGTH} characters")

    @staticmethod
    def _validate_entity_type(entity_type: str) -> str:
        entity = (entity_type or "").strip().upper()
        if not _ENTITY_TYPE_PATTERN.fullmatch(entity):
            raise ValueError("entity_type must match [A-Z][A-Z0-9_]* (max 32 characters)")
        return entity

    def __repr__(self) -> str:
        return f"TokenVault(ttl_seconds={self._ttl}, prefix={self._prefix!r})"


@functools.lru_cache(maxsize=1)
def get_vault() -> TokenVault:
    """Process-wide vault wired to the shared Redis client and settings key."""
    settings = get_settings()
    return TokenVault(
        get_redis(settings.redis_url, max_connections=settings.redis_max_connections),
        key=settings.vault_key_bytes,
        ttl_seconds=settings.vault_ttl_seconds,
    )
