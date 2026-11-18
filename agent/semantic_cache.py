"""Semantic completion cache in front of the model call (ADR-024).

The cache is a latency and cost device, not a control. It sits after DLP,
classification and routing, and a lookup is scoped by tenant, model alias and
classification label, so a turn can never read another tenant's answer or a
cloud answer for a confidential prompt. A turn that minted DLP markers is never
stored and never served: a marker is session-scoped, and replaying one under
another session would deliver an unresolved ``{{ENTITY:...}}`` token.

Redis is a cache here, not a ledger: every read and write is best-effort and a
failure degrades to a model call, because losing the cache must never lose a
turn.
"""

from __future__ import annotations

import json
import logging
from typing import Final, Protocol

from redis.asyncio import Redis
from redis.exceptions import RedisError

from agent.dlp.vault import TOKEN_PATTERN

logger = logging.getLogger(__name__)

_KEY_VERSION: Final = "v1"


class SimilarityBackend(Protocol):
    """How two prompts are compared; injected so tests need no model or network."""

    def score(self, left: str, right: str) -> float:
        """Return 0.0-1.0; 1.0 means "the same question"."""
        ...


class TokenSimilarity:
    """Deterministic Jaccard over word sets: on-box, no model and no network."""

    def score(self, left: str, right: str) -> float:
        left_tokens = set(left.lower().split())
        right_tokens = set(right.lower().split())
        union = left_tokens | right_tokens
        if not union:
            return 1.0
        return len(left_tokens & right_tokens) / len(union)


class SemanticCache:
    """Per-scope completion cache with a similarity threshold and a TTL."""

    def __init__(
        self,
        redis: Redis,
        *,
        backend: SimilarityBackend,
        threshold: float,
        ttl_seconds: int,
        max_entries: int,
    ) -> None:
        if not 0.0 < threshold <= 1.0:
            raise ValueError("similarity threshold must be in (0, 1]")
        if ttl_seconds <= 0 or max_entries <= 0:
            raise ValueError("ttl and max entries must be positive")
        self._redis = redis
        self._backend = backend
        self._threshold = threshold
        self._ttl = ttl_seconds
        self._max_entries = max_entries

    @staticmethod
    def _key(tenant_id: str, alias: str, label: str) -> str:
        """One scope per tenant, model alias and classification (ADR-024)."""
        return f"semantic_cache:{_KEY_VERSION}:{tenant_id}:{alias}:{label}"

    async def _load(self, key: str) -> list[dict[str, str]]:
        try:
            raw = await self._redis.get(key)
        except RedisError as exc:
            logger.warning("Semantic cache read failed", extra={"error": type(exc).__name__})
            return []
        if raw is None:
            return []
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return []
        entries = payload.get("entries") if isinstance(payload, dict) else None
        return [
            {"prompt": entry["prompt"], "answer": entry["answer"]}
            for entry in entries or []
            if isinstance(entry, dict)
            and isinstance(entry.get("prompt"), str)
            and isinstance(entry.get("answer"), str)
        ]

    async def lookup(self, *, tenant_id: str, alias: str, label: str, prompt: str) -> str | None:
        """The best answer at or above the threshold, or ``None`` on a miss."""
        best_score = -1.0
        best_answer: str | None = None
        for entry in await self._load(self._key(tenant_id, alias, label)):
            score = self._backend.score(prompt, entry["prompt"])
            if score > best_score:
                best_score = score
                best_answer = entry["answer"]
        if best_answer is None or best_score < self._threshold:
            return None
        if TOKEN_PATTERN.search(best_answer):
            # Minted in the storing session; unresolved in this one.
            return None
        return best_answer

    async def store(
        self, *, tenant_id: str, alias: str, label: str, prompt: str, answer: str
    ) -> None:
        """Remember one delivered answer, unless it carries a DLP marker."""
        if TOKEN_PATTERN.search(answer):
            return
        key = self._key(tenant_id, alias, label)
        entries = [entry for entry in await self._load(key) if entry["prompt"] != prompt]
        entries.append({"prompt": prompt, "answer": answer})
        try:
            await self._redis.set(
                key, json.dumps({"entries": entries[-self._max_entries :]}), ex=self._ttl
            )
        except RedisError as exc:
            logger.warning("Semantic cache write failed", extra={"error": type(exc).__name__})
