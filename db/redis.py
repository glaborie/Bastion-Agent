"""Process-wide async Redis client shared by sessions, the DLP vault and ARQ.

The client is created lazily so importing a module never opens a socket. Redis
is a trusted internal component: it holds the ARQ queue, opaque dashboard
sessions and the AES-256-GCM token vault. Every key namespace is owned by one
subsystem; nothing scans the keyspace.
"""

from __future__ import annotations

from redis.asyncio import Redis

_redis: Redis | None = None


def get_redis(redis_url: str, *, max_connections: int = 50) -> Redis:
    """Return the process-wide async Redis client."""
    global _redis
    if _redis is None:
        _redis = Redis.from_url(
            redis_url,
            decode_responses=True,
            max_connections=max_connections,
            socket_connect_timeout=5,
            socket_timeout=5,
            health_check_interval=30,
        )
    return _redis


async def close_redis() -> None:
    """Close the shared client (gateway/worker shutdown and tests)."""
    global _redis
    client, _redis = _redis, None
    if client is not None:
        await client.aclose()
