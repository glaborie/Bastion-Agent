"""Process-wide async Redis client shared by sessions, the DLP vault and ARQ.

The client is created lazily so importing a module never opens a socket. Redis
is a trusted internal component: it holds the ARQ queue, opaque dashboard
sessions and the AES-256-GCM token vault. Every key namespace is owned by one
subsystem; nothing scans the keyspace.

East-west TLS (ADR-019): when ``REDIS_TLS_ENABLED`` is set, or the DSN already
uses ``rediss://``, the client presents this service's certificate and requires
one from the server. A missing bundle fails closed here rather than connecting
in plaintext, which is the whole point of the ``pki`` profile.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from arq.connections import RedisSettings
from redis.asyncio import Redis

from settings import Settings, get_settings

_redis: Redis | None = None


def _require_file(path: str, purpose: str) -> str:
    if not Path(path).is_file():
        raise RuntimeError(f"{purpose} is missing at {path}; refusing a plaintext Redis connection")
    return path


def redis_tls_kwargs(settings: Settings, *, redis_url: str | None = None) -> dict[str, Any]:
    """TLS options for redis-py, or an empty dict when TLS is not in use.

    ``rediss://`` in the DSN is treated as an explicit request for TLS even when
    the boolean is unset, so an operator cannot enable the scheme and silently
    get a plaintext socket.
    """
    url = redis_url if redis_url is not None else settings.redis_url
    if not settings.redis_tls_enabled and not url.startswith("rediss://"):
        return {}
    return {
        "ssl_ca_certs": _require_file(settings.pki_ca_cert_path, "the Redis CA bundle"),
        "ssl_certfile": _require_file(settings.pki_client_cert_path, "this service's certificate"),
        "ssl_keyfile": _require_file(settings.pki_client_key_path, "this service's private key"),
        "ssl_cert_reqs": "required",
    }


def arq_redis_settings(settings: Settings | None = None) -> RedisSettings:
    """ARQ pool settings, including the east-west client identity."""
    config = settings or get_settings()
    redis_settings = RedisSettings.from_dsn(config.redis_url)
    tls = redis_tls_kwargs(config)
    if tls:
        redis_settings.ssl = True
        redis_settings.ssl_ca_certs = str(tls["ssl_ca_certs"])
        redis_settings.ssl_certfile = str(tls["ssl_certfile"])
        redis_settings.ssl_keyfile = str(tls["ssl_keyfile"])
        redis_settings.ssl_cert_reqs = str(tls["ssl_cert_reqs"])
    return redis_settings


def get_redis(redis_url: str, *, max_connections: int = 50) -> Redis:
    """Return the process-wide async Redis client."""
    global _redis
    if _redis is None:
        settings = get_settings()
        _redis = Redis.from_url(
            redis_url,
            decode_responses=True,
            max_connections=max_connections,
            socket_connect_timeout=5,
            socket_timeout=5,
            health_check_interval=30,
            **redis_tls_kwargs(settings, redis_url=redis_url),
        )
    return _redis


async def close_redis() -> None:
    """Close the shared client (gateway/worker shutdown and tests)."""
    global _redis
    client, _redis = _redis, None
    if client is not None:
        await client.aclose()
