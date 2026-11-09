"""Redis-backed session and login-state tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from fakeredis import FakeAsyncRedis
from redis.asyncio import Redis

from gateway.auth.oidc import (
    OAuthExchangeError,
    OIDCTokenClient,
    Principal,
    TokenSet,
    TokenValidationError,
    TokenValidator,
)
from gateway.auth.session import (
    SESSION_KEY_PREFIX,
    LoginState,
    SessionManager,
    SessionRecord,
    safe_next_path,
)

BOB = Principal(subject="bob-sub", username="bob", roles=frozenset({"operator"}))


class StubValidator:
    def __init__(self, principal: Principal = BOB, *, fail: bool = False) -> None:
        self.principal = principal
        self.fail = fail
        self.calls = 0

    async def validate_access_token(self, token: str) -> Principal:
        self.calls += 1
        if self.fail:
            raise TokenValidationError("invalid_token")
        return self.principal


class StubTokenClient:
    def __init__(
        self,
        tokens: TokenSet | None = None,
        *,
        error: OAuthExchangeError | None = None,
        delay: float = 0.0,
    ) -> None:
        self.tokens = tokens
        self.error = error
        self.delay = delay
        self.calls = 0

    async def refresh(self, *, refresh_token: str) -> TokenSet:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        if self.tokens is None:
            raise AssertionError("refresh called without a configured response")
        return self.tokens


def _tokens(**overrides: Any) -> TokenSet:
    base: dict[str, Any] = {
        "access_token": "access-1",
        "token_type": "Bearer",
        "expires_in": 300,
        "refresh_token": "refresh-1",
        "id_token": "id-1",
    }
    base.update(overrides)
    return TokenSet(**base)


async def _manager(
    *,
    validator: StubValidator | None = None,
    token_client: StubTokenClient | None = None,
    ttl_seconds: int = 3600,
    refresh_leeway_seconds: int = 60,
) -> tuple[SessionManager, FakeAsyncRedis]:
    redis = FakeAsyncRedis(decode_responses=True)
    manager = SessionManager(
        cast(Redis, redis),
        validator=cast(TokenValidator, validator or StubValidator()),
        token_client=cast(OIDCTokenClient, token_client or StubTokenClient()),
        ttl_seconds=ttl_seconds,
        refresh_leeway_seconds=refresh_leeway_seconds,
    )
    return manager, redis


async def test_create_persists_an_opaque_session_with_a_ttl() -> None:
    manager, redis = await _manager()
    record = await manager.create(_tokens())

    assert len(record.session_id) >= 32
    assert record.csrf_token and record.csrf_token != record.session_id
    assert await redis.exists(SESSION_KEY_PREFIX + record.session_id) == 1
    ttl = await redis.ttl(SESSION_KEY_PREFIX + record.session_id)
    assert 0 < ttl <= 3600

    resolved = await manager.resolve(record.session_id)
    assert resolved is not None
    assert resolved.principal.subject == "bob-sub"
    assert resolved.access_token == "access-1"


async def test_unknown_session_is_none() -> None:
    manager, _redis = await _manager()
    assert await manager.resolve("does-not-exist") is None
    assert await manager.resolve("") is None


async def test_expiring_token_is_refreshed_transparently() -> None:
    validator = StubValidator()
    refreshed = _tokens(access_token="access-2", refresh_token="refresh-2", expires_in=300)
    client = StubTokenClient(refreshed)
    manager, _redis = await _manager(validator=validator, token_client=client)

    record = await manager.create(_tokens())
    record.access_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await manager._save(record)

    resolved = await manager.resolve(record.session_id)
    assert resolved is not None
    assert resolved.access_token == "access-2"
    assert resolved.refresh_token == "refresh-2"
    assert client.calls == 1
    assert validator.calls == 2  # login + refresh


async def test_concurrent_resolution_refreshes_only_once() -> None:
    client = StubTokenClient(_tokens(access_token="access-2"), delay=0.2)
    manager, _redis = await _manager(token_client=client)
    record = await manager.create(_tokens())
    record.access_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await manager._save(record)

    first, second = await asyncio.gather(
        manager.resolve(record.session_id),
        manager.resolve(record.session_id),
    )
    assert first is not None and second is not None
    assert first.access_token == "access-2"
    assert second.access_token == "access-2"
    assert client.calls == 1


async def test_failed_refresh_deletes_the_session() -> None:
    client = StubTokenClient(error=OAuthExchangeError("invalid_grant"))
    manager, redis = await _manager(token_client=client)

    record = await manager.create(_tokens())
    record.access_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await manager._save(record)

    assert await manager.resolve(record.session_id) is None
    assert await redis.exists(SESSION_KEY_PREFIX + record.session_id) == 0


async def test_malformed_session_record_is_discarded() -> None:
    manager, redis = await _manager()
    await redis.set(SESSION_KEY_PREFIX + "bad", "{not json")
    assert await manager.resolve("bad") is None
    assert await redis.exists(SESSION_KEY_PREFIX + "bad") == 0


async def test_delete_is_idempotent() -> None:
    manager, redis = await _manager()
    record = await manager.create(_tokens())
    await manager.delete(record.session_id)
    await manager.delete(record.session_id)
    assert await redis.exists(SESSION_KEY_PREFIX + record.session_id) == 0


async def test_login_state_is_single_use() -> None:
    manager, _redis = await _manager()
    state = "state-abc"
    await manager.store_login_state(
        state,
        LoginState(nonce="nonce", code_verifier="verifier", next_path="/dashboard"),
    )
    first = await manager.pop_login_state(state)
    second = await manager.pop_login_state(state)
    assert first is not None
    assert first.nonce == "nonce"
    assert first.code_verifier == "verifier"
    assert second is None


def test_session_record_json_round_trip() -> None:
    now = datetime.now(UTC).replace(microsecond=123456)
    record = SessionRecord(
        session_id="sid",
        principal=BOB,
        access_token="a",
        refresh_token="r",
        id_token="i",
        csrf_token="csrf",
        created_at=now,
        access_expires_at=now + timedelta(minutes=5),
        last_seen_at=now,
    )
    restored = SessionRecord.from_json(record.to_json())
    assert restored.session_id == "sid"
    assert restored.principal.roles == frozenset({"operator"})
    assert restored.created_at == now
    assert restored.csrf_token == "csrf"


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("/dashboard", "/dashboard"),
        (
            "/dashboard/audit?event_type=INPUT_RECEIVED",
            "/dashboard/audit?event_type=INPUT_RECEIVED",
        ),
        (None, "/dashboard"),
        ("", "/dashboard"),
        ("https://evil.example/", "/dashboard"),
        ("//evil.example/", "/dashboard"),
        ("/\\evil", "/dashboard"),
        ("dashboard", "/dashboard"),
    ],
)
def test_safe_next_path_blocks_open_redirects(candidate: str | None, expected: str) -> None:
    assert safe_next_path(candidate) == expected
