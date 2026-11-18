"""Per-principal rate limiting at the dependency and HTTP layers (ADR-013).

The bucket algorithm is covered against a live Redis in
``tests/test_rate_limit_redis.py``. These tests cover the contract the routes
depend on: which scope is charged, which limit is applied, the response headers,
the fail-closed path and the dashboard's HTML rendering of a 429.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import httpx
import pytest
import pytest_asyncio
from fastapi import Request, Response

from db.session import get_db_session
from gateway.auth.oidc import Principal
from gateway.auth.rbac import AuthContext, get_auth_context
from gateway.main import create_app
from gateway.rate_limit import (
    RateLimitDecision,
    RateLimitUnavailable,
    estimate_prompt_tokens,
    get_rate_limiter,
    rate_limit,
    settled_tokens,
)
from settings import reset_settings_cache

BOB = Principal(subject="bob-sub", tenant_id="acme", username="bob", roles=frozenset({"operator"}))


@dataclass
class StubLimiter:
    """Deterministic stand-in for the Redis store; records every call."""

    allowed: bool = True
    retry_after_seconds: int = 1
    error: Exception | None = None
    calls: list[tuple[str, str, int, int]] = field(default_factory=list)
    costs: list[int] = field(default_factory=list)

    async def consume(
        self,
        principal_id: str,
        scope: str,
        *,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitDecision:
        self.calls.append((principal_id, scope, limit, window_seconds))
        self.costs.append(cost)
        if self.error is not None:
            raise self.error
        return RateLimitDecision(
            allowed=self.allowed,
            limit=limit,
            remaining=limit - 1 if self.allowed else 0,
            retry_after_seconds=0 if self.allowed else self.retry_after_seconds,
            reset_after_seconds=7,
        )


def _request(path: str, method: str = "GET") -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
        }
    )


@pytest_asyncio.fixture
async def api(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[tuple[httpx.AsyncClient, StubLimiter]]:
    """The real app, with auth and the limiter replaced at their seams."""
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    reset_settings_cache()
    app = create_app()
    stub = StubLimiter()

    async def _no_database() -> AsyncIterator[None]:
        yield None

    app.dependency_overrides[get_auth_context] = lambda: AuthContext(principal=BOB, method="bearer")
    app.dependency_overrides[get_rate_limiter] = lambda: stub
    app.dependency_overrides[get_db_session] = _no_database

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=False
    ) as client:
        yield client, stub


async def test_dashboard_api_charges_the_dashboard_scope(
    api: tuple[httpx.AsyncClient, StubLimiter],
) -> None:
    client, stub = api
    response = await client.get("/api/evals/latest")

    assert response.status_code == 200
    assert stub.calls == [("bob-sub", "dashboard", 60, 60)]
    assert response.headers["ratelimit-limit"] == "60"
    assert response.headers["ratelimit-remaining"] == "59"
    assert response.headers["ratelimit-reset"] == "7"
    assert "retry-after" not in response.headers


async def test_exceeded_budget_returns_429_with_retry_after(
    api: tuple[httpx.AsyncClient, StubLimiter],
) -> None:
    client, stub = api
    stub.allowed = False
    stub.retry_after_seconds = 12

    response = await client.get("/api/evals/latest")

    assert response.status_code == 429
    assert response.json()["detail"] == "rate limit exceeded"
    assert response.headers["retry-after"] == "12"
    assert response.headers["ratelimit-remaining"] == "0"


async def test_dashboard_page_renders_a_429_as_html(
    api: tuple[httpx.AsyncClient, StubLimiter],
) -> None:
    client, stub = api
    stub.allowed = False
    stub.retry_after_seconds = 3

    response = await client.get("/dashboard")

    assert response.status_code == 429
    assert "Too many requests" in response.text
    assert "3 seconds" in response.text
    assert response.headers["retry-after"] == "3"


async def test_limiter_outage_fails_closed_with_503(
    api: tuple[httpx.AsyncClient, StubLimiter],
) -> None:
    client, stub = api
    stub.error = RateLimitUnavailable("store down")

    response = await client.get("/api/evals/latest")

    assert response.status_code == 503
    assert response.json()["detail"] == "rate limiter unavailable"


async def test_chat_route_charges_the_chat_scope(
    api: tuple[httpx.AsyncClient, StubLimiter],
) -> None:
    client, stub = api
    stub.allowed = False

    response = await client.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 429
    assert stub.calls == [("bob-sub", "chat", 120, 60)]


async def test_health_probe_is_not_rate_limited(
    api: tuple[httpx.AsyncClient, StubLimiter],
) -> None:
    client, stub = api
    stub.allowed = False

    response = await client.get("/health")

    assert response.status_code == 200
    assert stub.calls == []


async def test_disabled_limiter_does_not_touch_the_store(
    api: tuple[httpx.AsyncClient, StubLimiter],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, stub = api
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    reset_settings_cache()

    response = await client.get("/api/evals/latest")

    assert response.status_code == 200
    assert stub.calls == []
    assert "ratelimit-limit" not in response.headers


async def test_chat_dependency_passes_the_configured_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Call the dependency directly, so the scope-to-setting mapping is pinned."""
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    reset_settings_cache()
    dependency = rate_limit("chat")
    stub = StubLimiter()
    response = Response()

    context = await dependency(  # type: ignore[call-arg]
        request=_request("/v1/chat", "POST"),
        response=response,
        context=AuthContext(principal=BOB, method="bearer"),
        limiter=stub,  # type: ignore[arg-type]
    )

    assert context.actor_id == "bob-sub"
    assert stub.calls == [("bob-sub", "chat", 120, 60)]
    assert response.headers["ratelimit-limit"] == "120"


async def test_htmx_partial_renders_the_429_page(
    api: tuple[httpx.AsyncClient, StubLimiter],
) -> None:
    client, stub = api
    stub.allowed = False
    stub.retry_after_seconds = 5

    response = await client.get("/api/approvals", headers={"HX-Request": "true"})

    assert response.status_code == 429
    assert "Too many requests" in response.text
    assert response.headers["retry-after"] == "5"


def test_unknown_scope_is_rejected_at_runtime() -> None:
    # The Literal type catches a typo in mypy; this keeps a dynamic caller from
    # silently receiving the dashboard budget for an unknown scope.
    with pytest.raises(ValueError, match="unknown rate limit scope"):
        rate_limit("dashbaord")  # type: ignore[arg-type]


def test_stub_limiter_signature_matches_the_protocol() -> None:
    """The stub and the real limiter must accept the same keyword arguments."""
    import inspect

    from gateway.rate_limit import RateLimiter

    real = inspect.signature(RateLimiter.consume)
    stub = inspect.signature(StubLimiter.consume)
    assert list(real.parameters) == list(stub.parameters)


class _Message:
    """Minimal ``ChatMessage`` stand-in: the estimator only reads ``content``."""

    def __init__(self, content: str) -> None:
        self.content = content


def test_the_estimator_is_ceil_chars_over_four_plus_four_per_message() -> None:
    # The message list a turn sends upstream, plus the output cap, is what the
    # bucket is charged: one short message costs 1 + 4 tokens.
    assert estimate_prompt_tokens([_Message("abcd")]) == 1 + 4
    # 8 characters round to 2 tokens, and each additional message carries 4.
    assert estimate_prompt_tokens([_Message("abcd"), _Message("efgh")]) == 2 + 8
    # Conservative on English on purpose; settlement refunds the difference.
    long_prompt = [_Message("a" * 4000)]
    assert estimate_prompt_tokens(long_prompt) == 1000 + 4


def test_the_estimator_counts_characters_not_bytes() -> None:
    # Four multi-byte characters are still one token at this ratio.
    assert estimate_prompt_tokens([_Message("héllo wörld")]) == 3 + 4


def test_settlement_prefers_total_then_the_two_parts() -> None:
    assert settled_tokens(prompt_tokens=10, completion_tokens=5, total_tokens=17) == 17
    assert settled_tokens(prompt_tokens=10, completion_tokens=5, total_tokens=None) == 15
    # A provider that omits usage is charged at its reservation (ADR-020).
    assert settled_tokens(prompt_tokens=None, completion_tokens=None, total_tokens=None) is None
    assert settled_tokens(prompt_tokens=None, completion_tokens=5, total_tokens=None) is None
