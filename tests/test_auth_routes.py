"""Authorization-code + PKCE login flow tests."""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, cast

import httpx
import pytest_asyncio
from fakeredis import FakeAsyncRedis
from redis.asyncio import Redis

from gateway.auth.oidc import (
    OIDCTokenClient,
    Principal,
    TokenValidationError,
    TokenValidator,
)
from gateway.auth.rbac import (
    get_session_manager,
    get_token_client,
    get_token_validator,
)
from gateway.auth.session import SESSION_KEY_PREFIX, SessionManager
from gateway.main import create_app

BOB = Principal(subject="bob-sub", username="bob", roles=frozenset({"operator"}))


class StubValidator:
    def __init__(self, *, id_token_error: str | None = None) -> None:
        self.id_token_error = id_token_error

    async def validate_access_token(self, token: str) -> Principal:
        return BOB

    async def validate_id_token(
        self, token: str, *, expected_nonce: str | None = None
    ) -> dict[str, Any]:
        if self.id_token_error:
            raise TokenValidationError(self.id_token_error)
        return {"sub": BOB.subject}


def _token_handler(request: httpx.Request) -> httpx.Response:
    form = urllib.parse.parse_qs((request.content or b"").decode())
    if form.get("grant_type") != ["authorization_code"]:
        return httpx.Response(400, json={"error": "unsupported_grant_type"})
    if form.get("code") == ["bad-code"]:
        return httpx.Response(400, json={"error": "invalid_grant"})
    return httpx.Response(
        200,
        json={
            "access_token": "access-1",
            "token_type": "Bearer",
            "expires_in": 300,
            "refresh_token": "refresh-1",
            "id_token": "id-1",
        },
    )


@pytest_asyncio.fixture
async def harness() -> Any:
    redis = FakeAsyncRedis(decode_responses=True)
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(_token_handler))
    token_client = OIDCTokenClient(
        token_endpoint="https://idp.test/token",
        authorization_endpoint="https://idp.test/auth",
        client_id="bastion-gateway",
        client_secret="dev-only-keycloak-client-secret",
        redirect_uri="http://localhost:8000/auth/callback",
        client=http_client,
    )
    validator = StubValidator()
    manager = SessionManager(
        cast(Redis, redis),
        validator=cast(TokenValidator, validator),
        token_client=cast(OIDCTokenClient, token_client),
    )
    app = create_app()
    app.dependency_overrides[get_session_manager] = lambda: manager
    app.dependency_overrides[get_token_client] = lambda: token_client
    app.dependency_overrides[get_token_validator] = lambda: validator

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        follow_redirects=False,
    ) as client:
        yield {
            "client": client,
            "redis": redis,
            "manager": manager,
            "validator": validator,
            "token_client": token_client,
            "app": app,
        }
    await http_client.aclose()


async def test_login_redirects_with_state_nonce_and_pkce(harness: Any) -> None:
    response = await harness["client"].get("/auth/login", params={"next": "https://evil.example"})
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("https://idp.test/auth?")
    params = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    assert params["client_id"] == ["bastion-gateway"]
    assert params["response_type"] == ["code"]
    assert params["redirect_uri"] == ["http://localhost:8000/auth/callback"]
    assert params["code_challenge_method"] == ["S256"]
    assert len(params["state"][0]) >= 32
    assert len(params["nonce"][0]) >= 32
    assert len(params["code_challenge"][0]) >= 43
    assert response.headers["cache-control"] == "no-store"

    state = params["state"][0]
    stored = await harness["redis"].get("auth:oidc-state:" + state)
    assert stored is not None
    assert harness["redis"] is not None


async def test_callback_creates_a_server_side_session(harness: Any) -> None:
    login = await harness["client"].get("/auth/login", params={"next": "/dashboard/audit"})
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(login.headers["location"]).query)["state"][
        0
    ]

    response = await harness["client"].get(
        "/auth/callback", params={"code": "good-code", "state": state}
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard/audit"
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie

    session_id = harness["client"].cookies.get("bastion_session")
    assert session_id
    assert await harness["redis"].exists(SESSION_KEY_PREFIX + session_id) == 1


async def test_callback_state_is_single_use(harness: Any) -> None:
    login = await harness["client"].get("/auth/login")
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(login.headers["location"]).query)["state"][
        0
    ]

    first = await harness["client"].get(
        "/auth/callback", params={"code": "good-code", "state": state}
    )
    second = await harness["client"].get(
        "/auth/callback", params={"code": "good-code", "state": state}
    )
    assert first.status_code == 303
    assert second.status_code == 303
    assert second.headers["location"].startswith("/auth/error?reason=state_expired")


async def test_unknown_state_is_rejected(harness: Any) -> None:
    response = await harness["client"].get(
        "/auth/callback", params={"code": "good-code", "state": "forged"}
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/auth/error?reason=state_expired")


async def test_denied_authorization_is_reported(harness: Any) -> None:
    response = await harness["client"].get("/auth/callback", params={"error": "access_denied"})
    assert response.status_code == 303
    assert response.headers["location"].startswith("/auth/error?reason=access_denied")


async def test_rejected_code_exchange_is_reported(harness: Any) -> None:
    login = await harness["client"].get("/auth/login")
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(login.headers["location"]).query)["state"][
        0
    ]
    response = await harness["client"].get(
        "/auth/callback", params={"code": "bad-code", "state": state}
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/auth/error?reason=exchange_failed")


async def test_invalid_id_token_nonce_is_reported(harness: Any) -> None:
    harness["validator"].id_token_error = "invalid_nonce"
    login = await harness["client"].get("/auth/login")
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(login.headers["location"]).query)["state"][
        0
    ]
    response = await harness["client"].get(
        "/auth/callback", params={"code": "good-code", "state": state}
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/auth/error?reason=id_token_invalid")


async def test_me_accepts_a_bearer_token(harness: Any) -> None:
    response = await harness["client"].get(
        "/auth/me", headers={"Authorization": "Bearer opaque-token"}
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["subject"] == "bob-sub"
    assert payload["roles"] == ["operator"]
    assert payload["method"] == "bearer"


async def test_logout_deletes_the_session_and_requires_csrf(harness: Any) -> None:
    login = await harness["client"].get("/auth/login")
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(login.headers["location"]).query)["state"][
        0
    ]
    await harness["client"].get("/auth/callback", params={"code": "good-code", "state": state})
    session_id = harness["client"].cookies.get("bastion_session")
    assert session_id

    without_csrf = await harness["client"].post("/auth/logout")
    assert without_csrf.status_code == 403

    raw = await harness["redis"].get(SESSION_KEY_PREFIX + session_id)
    csrf = json.loads(raw)["csrf_token"]
    response = await harness["client"].post(
        "/auth/logout", headers={"X-CSRF-Token": csrf, "Origin": "null"}
    )
    assert response.status_code == 303
    landing_url = response.headers["location"]
    assert landing_url.startswith("/auth/logged-out?t=")
    assert any(
        "bastion_logged_out=1" in cookie for cookie in response.headers.get_list("set-cookie")
    )
    assert await harness["redis"].exists(SESSION_KEY_PREFIX + session_id) == 0

    landing = await harness["client"].get(landing_url)
    assert landing.status_code == 200
    assert "/protocol/openid-connect/logout" in landing.text
    assert 'http-equiv="refresh"' in landing.text

    # The hand-off is single-use: reloading the landing page no longer exposes
    # an end-session URL (and therefore no id_token_hint).
    replay = await harness["client"].get(landing_url)
    assert replay.status_code == 200
    assert "Signed out" in replay.text
    assert 'http-equiv="refresh"' not in replay.text


async def test_login_forces_credentials_while_a_logout_is_in_flight(harness: Any) -> None:
    harness["client"].cookies.set("bastion_logged_out", "1")
    response = await harness["client"].get("/auth/login")
    assert response.status_code == 303
    params = urllib.parse.parse_qs(urllib.parse.urlsplit(response.headers["location"]).query)
    assert params["prompt"] == ["login"]
