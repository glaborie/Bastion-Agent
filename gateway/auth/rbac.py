"""FastAPI authentication and declarative RBAC dependencies (ADR-001/ADR-003).

Every protected route depends on :func:`get_auth_context`, which accepts either a
Bearer access token or an opaque dashboard session cookie. :func:`require_roles`
is the only authorization primitive: routes declare the roles they need and the
admin superset is applied in exactly one place.
"""

from __future__ import annotations

import functools
import hmac
import logging
import urllib.parse
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from fastapi import Depends, HTTPException, Request, status

from db.redis import close_redis, get_redis
from gateway.auth.oidc import (
    JWKSClient,
    OIDCTokenClient,
    Principal,
    TokenValidationError,
    TokenValidator,
    parse_bearer_token,
)
from gateway.auth.roles import ROLE_NAMES, any_satisfied
from gateway.auth.session import SessionManager, SessionRecord
from settings import get_settings

logger = logging.getLogger(__name__)

AuthMethod = Literal["bearer", "session"]

CSRF_HEADER = "X-CSRF-Token"
_WWW_AUTHENTICATE = {"WWW-Authenticate": 'Bearer realm="bastion"'}


@dataclass(frozen=True, slots=True)
class AuthContext:
    """The authenticated caller plus how the credential was presented."""

    principal: Principal
    method: AuthMethod
    session: SessionRecord | None = None

    @property
    def actor_id(self) -> str:
        """Stable audit identity: the JWT ``sub``, never a display name."""
        return self.principal.subject

    @property
    def csrf_token(self) -> str | None:
        return self.session.csrf_token if self.session is not None else None


# ---------------------------------------------------------------------------
# Process-wide clients
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def get_jwks_client() -> JWKSClient:
    settings = get_settings()
    return JWKSClient(
        settings.keycloak_jwks_url,
        cache_ttl_seconds=settings.keycloak_jwks_cache_ttl_seconds,
        min_refresh_seconds=settings.keycloak_jwks_min_refresh_seconds,
        timeout_seconds=settings.keycloak_http_timeout_seconds,
    )


@functools.lru_cache(maxsize=1)
def get_token_validator() -> TokenValidator:
    settings = get_settings()
    return TokenValidator(
        issuer=settings.keycloak_issuer,
        audience=settings.keycloak_audience,
        client_id=settings.keycloak_client_id,
        jwks=get_jwks_client(),
        leeway_seconds=settings.keycloak_leeway_seconds,
    )


@functools.lru_cache(maxsize=1)
def get_token_client() -> OIDCTokenClient:
    settings = get_settings()
    return OIDCTokenClient(
        token_endpoint=settings.keycloak_token_endpoint,
        authorization_endpoint=settings.keycloak_authorization_endpoint,
        client_id=settings.keycloak_client_id,
        client_secret=settings.keycloak_client_secret.get_secret_value(),
        redirect_uri=settings.keycloak_redirect_uri,
        scopes=settings.keycloak_scopes,
        timeout_seconds=settings.keycloak_http_timeout_seconds,
    )


@functools.lru_cache(maxsize=1)
def get_session_manager() -> SessionManager:
    settings = get_settings()
    return SessionManager(
        get_redis(settings.redis_url, max_connections=settings.redis_max_connections),
        validator=get_token_validator(),
        token_client=get_token_client(),
        ttl_seconds=settings.session_ttl_seconds,
        refresh_leeway_seconds=settings.session_refresh_leeway_seconds,
        login_state_ttl_seconds=settings.login_state_ttl_seconds,
        logout_target_ttl_seconds=settings.logout_target_ttl_seconds,
    )


async def shutdown_auth() -> None:
    """Release HTTP clients and the Redis connection (gateway shutdown)."""
    import asyncio

    closers = []
    if get_token_client.cache_info().currsize:
        closers.append(get_token_client().aclose())
    if get_jwks_client.cache_info().currsize:
        closers.append(get_jwks_client().aclose())

    for cache in (
        get_session_manager,
        get_token_client,
        get_token_validator,
        get_jwks_client,
    ):
        cache.cache_clear()

    if closers:
        await asyncio.gather(*closers, return_exceptions=True)
    await close_redis()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="authentication required",
        headers=_WWW_AUTHENTICATE,
    )


async def get_auth_context(
    request: Request,
    validator: TokenValidator = Depends(get_token_validator),
    sessions: SessionManager = Depends(get_session_manager),
) -> AuthContext:
    """Resolve the caller from a Bearer token or a dashboard session cookie."""
    settings = get_settings()
    header = request.headers.get("authorization")
    if header is not None:
        token = parse_bearer_token(header)
        if token is None:
            raise _unauthorized()
        try:
            principal = await validator.validate_access_token(token)
        except TokenValidationError as exc:
            # Log the stable reason code only — never the token or claim set.
            logger.info("Bearer token rejected", extra={"reason": exc.code})
            raise _unauthorized() from exc
        return AuthContext(principal=principal, method="bearer")

    session_id = request.cookies.get(settings.session_cookie_name)
    if session_id:
        record = await sessions.resolve(session_id)
        if record is not None:
            return AuthContext(principal=record.principal, method="session", session=record)

    raise _unauthorized()


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


def _flatten_roles(roles: Sequence[str | Sequence[str]]) -> tuple[str, ...]:
    flattened: list[str] = []
    for role in roles:
        if isinstance(role, str):
            flattened.append(role)
        else:
            flattened.extend(role)
    if not flattened:
        raise ValueError("require_roles needs at least one role")
    unknown = sorted(set(flattened) - ROLE_NAMES)
    if unknown:
        raise ValueError(f"unknown role(s): {unknown}; expected {sorted(ROLE_NAMES)}")
    return tuple(flattened)


def require_roles(
    *roles: str | Sequence[str],
) -> Callable[..., Awaitable[AuthContext]]:
    """Dependency factory enforcing **any-of** role membership.

    ``admin`` satisfies every requirement (break-glass superset). Other roles
    are independent grants, so ``operator`` does not implicitly grant
    ``analyst`` and vice versa.
    """
    required = _flatten_roles(roles)

    async def dependency(context: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if not any_satisfied(context.principal.roles, required):
            logger.info(
                "Authorization denied",
                extra={
                    "subject": context.principal.subject,
                    "granted": sorted(context.principal.roles),
                    "required": list(required),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insufficient role",
            )
        return context

    return dependency


# ---------------------------------------------------------------------------
# CSRF (session-authenticated mutations only)
# ---------------------------------------------------------------------------


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _origin_host(value: str) -> tuple[str, int] | None:
    """Return ``(hostname, port)`` for an Origin/Referer value, if parseable."""
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if not parsed.hostname:
        return None
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.hostname.lower(), port


def _same_origin(request: Request) -> bool:
    """Compare the browser-declared origin with the request origin.

    Host/port are compared rather than the full URL because a TLS-terminating
    proxy may report a different scheme back to the app. Loopback aliases are
    treated as equivalent: Windows/WSL and Docker Desktop port forwarding can
    rewrite ``localhost`` to ``127.0.0.1`` between the browser and the gateway,
    which is still the same machine and not a CSRF boundary.
    """
    declared = request.headers.get("origin") or request.headers.get("referer")
    if declared is None:
        # Non-browser clients do not send Origin; the CSRF token still applies.
        return True
    if declared.strip().lower() == "null":
        # Sandboxed/embedded browser contexts (opaque origin) send
        # "Origin: null" even for a same-page form. The per-session CSRF token
        # has already been verified, and a cross-origin attacker cannot read
        # it; the origin check is defence in depth, not the primary control.
        return True
    candidate = _origin_host(declared)
    expected = _origin_host(str(request.base_url))
    if candidate is None or expected is None:
        return False
    if candidate == expected:
        return True
    return (
        candidate[0] in _LOOPBACK_HOSTS
        and expected[0] in _LOOPBACK_HOSTS
        and candidate[1] == expected[1]
    )


async def require_csrf(
    request: Request,
    context: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    """Reject cross-site mutations for cookie-authenticated callers.

    Bearer-token callers are exempt: their credential is not ambient, so a
    browser cannot attach it to a forged request.
    """
    if context.method == "bearer":
        return context
    if context.session is None:
        raise _unauthorized()

    presented = request.headers.get(CSRF_HEADER)
    if presented is None:
        content_type = request.headers.get("content-type", "")
        if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
            form = await request.form()
            value = form.get("csrf_token")
            presented = value if isinstance(value, str) else None
    if not presented or not hmac.compare_digest(presented, context.session.csrf_token):
        logger.warning("CSRF check failed", extra={"subject": context.principal.subject})
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid",
        )
    if not _same_origin(request):
        logger.warning(
            "Cross-origin mutation blocked",
            extra={
                "subject": context.principal.subject,
                "path": request.url.path,
                "declared_origin": request.headers.get("origin"),
                "referer": request.headers.get("referer"),
                "sec_fetch_site": request.headers.get("sec-fetch-site"),
                "request_origin": str(request.base_url),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cross-origin request rejected",
        )
    return context
