"""Two agents of one owner must not share a budget (ADR-027, ADR-013/ADR-020).

The keys are the assertion: ``rate_limit_subject`` is the registry row's
``budget_key``, so exhausting one agent returns 429 while the other agent of the
same owner still reserves. Live Redis only — the bucket is a Lua script.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from typing import Final

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI
from redis.asyncio import Redis

from db.models import AgentRegistry
from gateway.auth.oidc import Principal
from gateway.auth.rbac import AuthContext, get_auth_context
from gateway.rate_limit import RateLimiter, get_rate_limiter, rate_limit
from settings import reset_settings_cache

REDIS_TEST_URL: Final[str] = os.getenv("REDIS_TEST_URL", "")

pytestmark = [
    pytest.mark.redis_integration,
    pytest.mark.skipif(not REDIS_TEST_URL, reason="REDIS_TEST_URL is not set"),
]


def _agent(agent_id: str, owner: str) -> AuthContext:
    return AuthContext(
        principal=Principal(
            subject=f"service-account-{agent_id}",
            tenant_id="acme",
            actor_type="agent",
            agent_id=agent_id,
        ),
        method="bearer",
        agent=AgentRegistry(
            agent_id=agent_id,
            owner_sub=owner,
            tenant_id="acme",
            allowed_tools=[],
            allowed_route_aliases=[],
            budget_key=f"agent:{agent_id}",
        ),
    )


def _app(redis: Redis, agent: AuthContext) -> FastAPI:
    app = FastAPI()
    app.dependency_overrides[get_rate_limiter] = lambda: RateLimiter(redis)
    app.dependency_overrides[get_auth_context] = lambda: agent

    @app.get("/limited")
    async def limited(_context: AuthContext = Depends(rate_limit("chat"))) -> dict[str, str]:
        return {"ok": "yes"}

    return app


@pytest_asyncio.fixture
async def redis_client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Redis]:
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_CHAT_PER_WINDOW", "2")
    reset_settings_cache()
    client = Redis.from_url(REDIS_TEST_URL, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()
        reset_settings_cache()


@pytest.mark.asyncio
async def test_two_agents_of_one_owner_have_independent_budgets(
    redis_client: Redis,
) -> None:
    first = _agent(f"agent-{uuid.uuid4()}", "alice-sub")
    second = _agent(f"agent-{uuid.uuid4()}", "alice-sub")
    assert first.owner_sub == second.owner_sub
    assert first.rate_limit_subject == f"agent:{first.agent_id}"
    assert first.rate_limit_subject != second.rate_limit_subject

    limiter = RateLimiter(redis_client)
    budget = {"limit": 2, "window_seconds": 60}
    try:
        assert (await limiter.consume(first.rate_limit_subject, "chat", **budget)).allowed
        assert (await limiter.consume(first.rate_limit_subject, "chat", **budget)).allowed
        assert not (await limiter.consume(first.rate_limit_subject, "chat", **budget)).allowed
        # The other agent of the same owner still has its whole budget.
        assert (await limiter.consume(second.rate_limit_subject, "chat", **budget)).allowed
    finally:
        for context in (first, second):
            await redis_client.delete(f"ratelimit:chat:{context.rate_limit_subject}")


@pytest.mark.asyncio
async def test_exhausted_agent_gets_429_from_the_dependency(redis_client: Redis) -> None:
    agent = _agent(f"agent-{uuid.uuid4()}", "alice-sub")
    try:
        transport = httpx.ASGITransport(app=_app(redis_client, agent))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            codes = [(await http.get("/limited")).status_code for _ in range(3)]
        assert codes == [200, 200, 429]
    finally:
        await redis_client.delete(f"ratelimit:chat:{agent.rate_limit_subject}")
