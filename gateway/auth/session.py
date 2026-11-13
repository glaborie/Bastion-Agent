"""Server-side dashboard sessions stored in Redis.

The browser never sees an access or refresh token: it only holds an opaque,
256-bit session identifier in an ``HttpOnly`` cookie. Token refresh happens
back-channel, so a five-minute Keycloak access token does not log an operator
out mid-incident.

Redis is a trusted component of the control plane (it already holds the ARQ
queue and, from Milestone 3, the encrypted token vault). Session records may
contain bearer material, so the Redis instance must stay on the internal network
with ``requirepass`` enabled — as `docker-compose.yml` does.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from collections.abc import Awaitable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final, cast

from redis.asyncio import Redis

from gateway.auth.oidc import (
    OAuthExchangeError,
    OIDCTokenClient,
    Principal,
    TokenSet,
    TokenValidationError,
    TokenValidator,
)
from gateway.auth.roles import normalise_roles

logger = logging.getLogger(__name__)

SESSION_KEY_PREFIX: Final[str] = "auth:session:"
#: Set of live session ids per subject, so sign-out can revoke the sessions a
#: replaced cookie no longer reaches. Membership is advisory: a session id is
#: only a session if its own key still exists.
SUBJECT_SESSIONS_KEY_PREFIX: Final[str] = "auth:subject-sessions:"
LOGIN_STATE_KEY_PREFIX: Final[str] = "auth:oidc-state:"
#: One-time hand-off of the Keycloak end-session URL from POST /auth/logout to
#: the GET landing page (PRG), so the old dashboard document is unloaded before
#: the browser leaves for the IdP.
LOGOUT_TARGET_KEY_PREFIX: Final[str] = "auth:logout-target:"
#: Short-lived lock serialising token refresh for one session. Keycloak rotates
#: refresh tokens on use, so two concurrent refreshes would otherwise revoke the
#: session.
REFRESH_LOCK_PREFIX: Final[str] = "auth:refresh-lock:"


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class SessionRecord:
    """Everything needed to service one logged-in browser session."""

    session_id: str
    principal: Principal
    access_token: str
    csrf_token: str
    created_at: datetime
    access_expires_at: datetime
    last_seen_at: datetime
    refresh_token: str | None = None
    id_token: str | None = None

    def to_json(self) -> str:
        return json.dumps(
            {
                "session_id": self.session_id,
                "principal": {
                    "subject": self.principal.subject,
                    "tenant_id": self.principal.tenant_id,
                    "username": self.principal.username,
                    "email": self.principal.email,
                    "roles": sorted(self.principal.roles),
                    "claims": self.principal.claims,
                },
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "id_token": self.id_token,
                "csrf_token": self.csrf_token,
                "created_at": self.created_at.isoformat(),
                "access_expires_at": self.access_expires_at.isoformat(),
                "last_seen_at": self.last_seen_at.isoformat(),
            }
        )

    @classmethod
    def from_json(cls, payload: str) -> SessionRecord:
        raw = json.loads(payload)
        if not isinstance(raw, dict):
            raise ValueError("session record is not an object")
        principal_raw = raw["principal"]
        if not isinstance(principal_raw, dict):
            raise ValueError("session principal is not an object")
        claims = principal_raw.get("claims")
        roles = principal_raw.get("roles")
        return cls(
            session_id=_require_str(raw, "session_id"),
            principal=Principal(
                subject=_require_str(principal_raw, "subject"),
                tenant_id=_require_str(principal_raw, "tenant_id"),
                username=_optional_str(principal_raw.get("username")),
                email=_optional_str(principal_raw.get("email")),
                roles=normalise_roles(roles if isinstance(roles, list) else []),
                claims=claims if isinstance(claims, dict) else {},
            ),
            access_token=_require_str(raw, "access_token"),
            refresh_token=_optional_str(raw.get("refresh_token")),
            id_token=_optional_str(raw.get("id_token")),
            csrf_token=_require_str(raw, "csrf_token"),
            created_at=_require_datetime(raw, "created_at"),
            access_expires_at=_require_datetime(raw, "access_expires_at"),
            last_seen_at=_require_datetime(raw, "last_seen_at"),
        )


@dataclass(frozen=True, slots=True)
class LoginState:
    """One-time state carried through the authorization-code redirect."""

    nonce: str
    code_verifier: str
    next_path: str
    created_at: datetime = field(default_factory=utcnow)


class SessionManager:
    """Create, resolve, refresh and delete server-side sessions."""

    def __init__(
        self,
        redis: Redis,
        *,
        validator: TokenValidator,
        token_client: OIDCTokenClient,
        ttl_seconds: int = 28800,
        refresh_leeway_seconds: int = 60,
        login_state_ttl_seconds: int = 600,
        logout_target_ttl_seconds: int = 120,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("session TTL must be positive")
        self._redis = redis
        self._validator = validator
        self._token_client = token_client
        self._ttl = ttl_seconds
        self._refresh_leeway = max(0, refresh_leeway_seconds)
        self._login_state_ttl = login_state_ttl_seconds
        self._logout_target_ttl = logout_target_ttl_seconds

    # -- sessions ---------------------------------------------------------
    async def create(self, tokens: TokenSet) -> SessionRecord:
        """Validate the access token, then persist a new session."""
        principal = await self._validator.validate_access_token(tokens.access_token)
        now = utcnow()
        record = SessionRecord(
            session_id=secrets.token_urlsafe(32),
            principal=principal,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            id_token=tokens.id_token,
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            access_expires_at=now + timedelta(seconds=tokens.expires_in),
            last_seen_at=now,
        )
        await self._save(record)
        return record

    async def resolve(self, session_id: str) -> SessionRecord | None:
        """Return a live session, refreshing tokens when they are about to expire."""
        if not session_id or len(session_id) > 256:
            return None
        key = SESSION_KEY_PREFIX + session_id
        payload = await self._redis.get(key)
        if payload is None:
            return None
        try:
            record = SessionRecord.from_json(payload)
        except (KeyError, TypeError, ValueError):
            logger.warning("Discarding a malformed session record")
            await self._redis.delete(key)
            return None
        if record.session_id != session_id:
            logger.warning("Session id mismatch; discarding the record")
            await self._redis.delete(key)
            return None

        if record.access_expires_at <= utcnow() + timedelta(seconds=self._refresh_leeway):
            refreshed = await self._refresh_with_lock(record)
            if refreshed is None:
                return None
            record = refreshed

        record.last_seen_at = utcnow()
        await self._save(record)
        return record

    async def _refresh_with_lock(self, record: SessionRecord) -> SessionRecord | None:
        """Refresh once per session even if several requests expire together."""
        key = SESSION_KEY_PREFIX + record.session_id
        lock_key = REFRESH_LOCK_PREFIX + record.session_id
        acquired = await self._redis.set(lock_key, "1", nx=True, ex=15)
        if not acquired:
            current = record
            for _ in range(50):
                await asyncio.sleep(0.1)
                payload = await self._redis.get(key)
                if payload is None:
                    return None
                try:
                    current = SessionRecord.from_json(payload)
                except (KeyError, TypeError, ValueError):
                    return None
                if current.access_expires_at > utcnow() + timedelta(seconds=self._refresh_leeway):
                    return current
            # The lock holder died or failed. The token is still valid for a
            # short while; let the next request try again rather than log out.
            return current

        try:
            payload = await self._redis.get(key)
            if payload is not None:
                try:
                    current = SessionRecord.from_json(payload)
                except (KeyError, TypeError, ValueError):
                    await self.delete(record.session_id)
                    return None
                if current.access_expires_at > utcnow() + timedelta(seconds=self._refresh_leeway):
                    return current
                record = current
            return await self._refresh(record)
        finally:
            await self._redis.delete(lock_key)

    async def _refresh(self, record: SessionRecord) -> SessionRecord | None:
        if not record.refresh_token:
            await self.delete(record.session_id)
            return None
        try:
            tokens = await self._token_client.refresh(refresh_token=record.refresh_token)
            principal = await self._validator.validate_access_token(tokens.access_token)
        except (OAuthExchangeError, TokenValidationError) as exc:
            logger.info(
                "Session refresh failed; logging the operator out",
                extra={"reason": getattr(exc, "error", getattr(exc, "code", "unknown"))},
            )
            await self.delete(record.session_id)
            return None

        now = utcnow()
        record.principal = principal
        record.access_token = tokens.access_token
        if tokens.refresh_token:
            record.refresh_token = tokens.refresh_token
        if tokens.id_token:
            record.id_token = tokens.id_token
        record.access_expires_at = now + timedelta(seconds=tokens.expires_in)
        record.last_seen_at = now
        logger.debug("Session tokens refreshed", extra={"subject": principal.subject})
        return record

    async def delete(self, session_id: str) -> None:
        if session_id:
            key = SESSION_KEY_PREFIX + session_id
            subject = _indexed_subject(await self._redis.get(key))
            await cast(Awaitable[int], self._redis.delete(key))
            if subject is not None:
                await cast(
                    Awaitable[int],
                    self._redis.srem(SUBJECT_SESSIONS_KEY_PREFIX + subject, session_id),
                )

    async def delete_all_for_subject(self, subject: str) -> int:
        """Revoke every live session of one subject; return how many were live.

        Sign-in replaces the shared cookie without retiring the session it used
        to point at, so sessions accumulate for a subject. Sign-out is where the
        operator expects them all to end. The per-subject set is the only index;
        an id whose session key has expired is deleted as a no-op and pruned
        with the rest of the set.
        """
        if not subject:
            return 0
        index = SUBJECT_SESSIONS_KEY_PREFIX + subject
        # redis-py types an unparameterised client's coroutine methods as
        # ``T | Awaitable[T]``; the Redis client here is always async.
        members = await cast(Awaitable[set[str]], self._redis.smembers(index))
        keys = [SESSION_KEY_PREFIX + str(member) for member in members]
        deleted = int(await cast(Awaitable[int], self._redis.delete(*keys))) if keys else 0
        await self._redis.delete(index)
        return deleted

    async def _save(self, record: SessionRecord) -> None:
        await self._redis.set(
            SESSION_KEY_PREFIX + record.session_id,
            record.to_json(),
            ex=self._ttl,
        )
        index = SUBJECT_SESSIONS_KEY_PREFIX + record.principal.subject
        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.sadd(index, record.session_id)
            pipe.expire(index, self._ttl)
            await pipe.execute()

    # -- login state ------------------------------------------------------
    async def store_login_state(self, state: str, value: LoginState) -> None:
        await self._redis.set(
            LOGIN_STATE_KEY_PREFIX + state,
            json.dumps(
                {
                    "nonce": value.nonce,
                    "code_verifier": value.code_verifier,
                    "next_path": value.next_path,
                    "created_at": value.created_at.isoformat(),
                }
            ),
            ex=self._login_state_ttl,
        )

    async def pop_login_state(self, state: str) -> LoginState | None:
        """Read and delete a state record, so a callback cannot be replayed."""
        if not state or len(state) > 256:
            return None
        payload = await self._redis.getdel(LOGIN_STATE_KEY_PREFIX + state)
        if payload is None:
            return None
        try:
            raw = json.loads(payload)
            if not isinstance(raw, dict):
                return None
            return LoginState(
                nonce=_require_str(raw, "nonce"),
                code_verifier=_require_str(raw, "code_verifier"),
                next_path=_require_str(raw, "next_path"),
                created_at=_require_datetime(raw, "created_at"),
            )
        except (KeyError, TypeError, ValueError):
            logger.warning("Discarding a malformed login-state record")
            return None

    # -- logout hand-off --------------------------------------------------
    async def store_logout_target(self, end_session_url: str) -> str:
        """Persist the IdP end-session URL under a one-time, short-lived key."""
        token = secrets.token_urlsafe(32)
        await self._redis.set(
            LOGOUT_TARGET_KEY_PREFIX + token,
            end_session_url,
            ex=self._logout_target_ttl,
        )
        return token

    async def pop_logout_target(self, token: str) -> str | None:
        """Read and delete the end-session URL (the landing page is single-use)."""
        if not token or len(token) > 256:
            return None
        payload = await self._redis.getdel(LOGOUT_TARGET_KEY_PREFIX + token)
        if not isinstance(payload, str) or not payload:
            return None
        return payload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def safe_next_path(value: str | None, *, default: str = "/dashboard") -> str:
    """Reject absolute URLs and protocol-relative paths (open-redirect guard)."""
    if not value:
        return default
    candidate = value.strip()
    if not candidate.startswith("/") or candidate.startswith("//"):
        return default
    if any(char in candidate for char in ("\r", "\n", "\\")):
        return default
    if "://" in candidate:
        return default
    return candidate


def _indexed_subject(payload: str | None) -> str | None:
    """Best-effort subject of a stored session record, for index cleanup."""
    if not payload:
        return None
    try:
        principal = json.loads(payload)["principal"]
    except (KeyError, TypeError, ValueError):
        return None
    subject = principal.get("subject") if isinstance(principal, dict) else None
    return subject if isinstance(subject, str) and subject else None


def _require_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"session field {key!r} is missing or invalid")
    return value


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _require_datetime(raw: dict[str, Any], key: str) -> datetime:
    value = raw.get(key)
    if not isinstance(value, str):
        raise ValueError(f"session field {key!r} is missing")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
