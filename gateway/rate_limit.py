"""Per-principal request rate limiting (ADR-013).

The bucket lives in Redis, so every gateway replica enforces one budget per
principal instead of one per process. Refill and consume happen inside a single
Lua script and the clock is Redis's own ``TIME``, which keeps replicas with
skewed system clocks from disagreeing about the same bucket.

Two scopes are enforced, both keyed on the JWT ``sub``:

* ``dashboard`` — pages, HTMX partials and the JSON APIs the dashboard polls
  (approvals, audit, eval health). The budget is deliberately the tighter one:
  a browser that polls faster than the UI needs is the common accident.
* ``chat`` — ``POST /v1/chat``, the only path that spends inference tokens.

Health probes, the OIDC login/callback routes and static assets are not
limited: they either have no principal yet or must stay reachable while the rest
of the stack is saturated. Login throttling belongs to Keycloak's brute-force
protection, which owns the credential check.

A limiter outage fails **closed** with ``503``. Redis already holds the token
vault and the canary registry, so an unreachable Redis already denies chat; the
rate limiter must not be the one control that silently degrades to "unlimited".
"""

from __future__ import annotations

import functools
import logging
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final, Literal, cast

from fastapi import Depends, HTTPException, Request, Response, status
from redis.asyncio import Redis
from redis.exceptions import RedisError

from db.redis import get_redis
from gateway.auth.rbac import AuthContext, get_auth_context
from settings import Settings, get_settings

logger = logging.getLogger(__name__)

RateLimitScope = Literal["dashboard", "chat"]

_SCOPES: Final[frozenset[str]] = frozenset({"dashboard", "chat"})

#: Token bucket, refilled continuously at ``capacity / window`` per millisecond.
#: ``TIME`` is read inside the script so all replicas share one clock. The key
#: expires once the bucket would be full again, so an idle principal leaves no
#: residue behind. Returns {allowed, remaining, retry_after_ms, reset_after_ms}.
_BUCKET_SCRIPT: Final[str] = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
if capacity <= 0 or window_ms <= 0 or cost <= 0 then
  return redis.error_reply('rate limiter: capacity, window and cost must be positive')
end

local refill = capacity / window_ms
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)

local state = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil or ts == nil then
  tokens = capacity
  ts = now
end

local elapsed = now - ts
if elapsed > 0 then
  tokens = math.min(capacity, tokens + elapsed * refill)
end

local allowed = 0
if tokens >= cost then
  allowed = 1
  tokens = tokens - cost
end

local retry_ms = 0
if allowed == 0 then
  retry_ms = math.ceil((cost - tokens) / refill)
end
local reset_ms = math.ceil((capacity - tokens) / refill)

redis.call('HSET', key, 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', key, math.max(reset_ms, 1000))

return {allowed, math.floor(tokens), retry_ms, reset_ms}
"""


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Outcome of one bucket consume, already converted to wire units."""

    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int
    reset_after_seconds: int


class RateLimitUnavailable(RuntimeError):
    """The limiter store could not answer, so the request must be refused."""


class RateLimiter:
    """Redis-backed token bucket shared by every gateway replica."""

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def consume(
        self,
        principal_id: str,
        scope: RateLimitScope,
        *,
        limit: int,
        window_seconds: int,
    ) -> RateLimitDecision:
        """Take one token from ``principal_id``'s ``scope`` bucket."""
        key = f"ratelimit:{scope}:{principal_id}"
        try:
            reply = await cast(
                "Awaitable[object]",
                self._redis.eval(
                    _BUCKET_SCRIPT,
                    1,
                    key,
                    str(limit),
                    str(window_seconds * 1000),
                    "1",
                ),
            )
        except RedisError as exc:
            logger.error("Rate limiter store unavailable", extra={"scope": scope})
            raise RateLimitUnavailable("rate limiter store unavailable") from exc

        if not isinstance(reply, (list, tuple)) or len(reply) != 4:
            logger.error("Rate limiter returned an unexpected reply", extra={"scope": scope})
            raise RateLimitUnavailable("rate limiter returned an unexpected reply")

        allowed, remaining, retry_ms, reset_ms = (int(str(value)) for value in reply)
        return RateLimitDecision(
            allowed=bool(allowed),
            limit=limit,
            remaining=max(0, remaining),
            retry_after_seconds=max(0, math.ceil(retry_ms / 1000)),
            reset_after_seconds=max(0, math.ceil(reset_ms / 1000)),
        )


@functools.lru_cache(maxsize=1)
def get_rate_limiter() -> RateLimiter:
    """Process-wide limiter over the shared Redis client."""
    settings = get_settings()
    return RateLimiter(
        get_redis(settings.redis_url, max_connections=settings.redis_max_connections)
    )


def _limit_for(scope: RateLimitScope, settings: Settings) -> int:
    if scope == "chat":
        return settings.rate_limit_chat_per_window
    return settings.rate_limit_dashboard_per_window


def _headers(decision: RateLimitDecision) -> dict[str, str]:
    """Draft ``RateLimit-*`` fields describing the bucket after this request."""
    return {
        "RateLimit-Limit": str(decision.limit),
        "RateLimit-Remaining": str(decision.remaining),
        "RateLimit-Reset": str(decision.reset_after_seconds),
    }


def _refusal_headers(decision: RateLimitDecision) -> dict[str, str]:
    """The 429 headers: bucket state plus when the caller may retry."""
    return {
        **_headers(decision),
        "Retry-After": str(decision.retry_after_seconds),
    }


def rate_limit(scope: RateLimitScope) -> Callable[..., Awaitable[AuthContext]]:
    """Dependency factory enforcing one scope's budget for the caller."""
    if scope not in _SCOPES:
        raise ValueError(f"unknown rate limit scope: {scope}")

    async def dependency(
        request: Request,
        response: Response,
        context: AuthContext = Depends(get_auth_context),
        limiter: RateLimiter = Depends(get_rate_limiter),
    ) -> AuthContext:
        settings = get_settings()
        if not settings.rate_limit_enabled:
            return context

        limit = _limit_for(scope, settings)
        try:
            decision = await limiter.consume(
                context.actor_id,
                scope,
                limit=limit,
                window_seconds=settings.rate_limit_window_seconds,
            )
        except RateLimitUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="rate limiter unavailable",
            ) from exc

        response.headers.update(_headers(decision))
        if not decision.allowed:
            logger.warning(
                "Rate limit exceeded",
                extra={
                    "subject": context.actor_id,
                    "scope": scope,
                    "limit": limit,
                    "path": request.url.path,
                    "retry_after_seconds": decision.retry_after_seconds,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="rate limit exceeded",
                headers=_refusal_headers(decision),
            )
        return context

    return dependency
