"""OIDC token validation with an async JWKS cache (ADR-001).

Keycloak issues RS256 access tokens. The gateway validates them locally:

* the JWKS document is fetched over the internal network and cached by ``kid``
  (never by token), with a bounded refresh rate so a client cannot force a fetch
  storm by presenting random key ids;
* only ``RS256`` is accepted — ``none``, HMAC and RSA-with-PSS algorithms are
  rejected before the signature is checked, which closes the classic key
  confusion attacks;
* issuer, audience and lifetime are always verified, with a small clock skew.

The browser login flow lives in :mod:`gateway.routers.auth`; this module only
validates tokens and talks to the token endpoint.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    MissingRequiredClaimError,
    PyJWTError,
)

from gateway.auth.roles import normalise_roles

logger = logging.getLogger(__name__)

#: Access tokens are small; anything longer is a DoS attempt or a mistake.
MAX_TOKEN_LENGTH: Final[int] = 8192

_ALGORITHM: Final[str] = "RS256"


# ---------------------------------------------------------------------------
# Errors and value objects
# ---------------------------------------------------------------------------


class TokenValidationError(Exception):
    """A token was rejected.

    ``code`` is a stable, non-sensitive reason used for metrics and logs. The
    message is deliberately generic so it cannot be reflected back to a caller
    with details that help an attacker.
    """

    def __init__(self, code: str, message: str = "invalid authentication token") -> None:
        super().__init__(message)
        self.code = code


class JWKSFetchError(RuntimeError):
    """The JWKS document could not be retrieved or contained no usable keys."""


class OAuthExchangeError(RuntimeError):
    """The token endpoint rejected an authorization-code or refresh grant."""

    def __init__(self, error: str, description: str | None = None) -> None:
        super().__init__(description or error)
        self.error = error
        self.description = description


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated identity derived from a validated access token."""

    subject: str
    username: str | None = None
    email: str | None = None
    roles: frozenset[str] = frozenset()
    #: Full claim set. Excluded from equality/repr so it can never leak through
    #: an exception traceback or a debugging log line.
    claims: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @property
    def display_name(self) -> str:
        return self.username or self.email or self.subject

    @property
    def expires_at(self) -> datetime | None:
        exp = self.claims.get("exp")
        if isinstance(exp, int | float):
            return datetime.fromtimestamp(float(exp), tz=UTC)
        return None


@dataclass(frozen=True, slots=True)
class TokenSet:
    """The subset of a token response the gateway needs."""

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None


@dataclass(frozen=True, slots=True)
class PKCEPair:
    verifier: str
    challenge: str


def generate_pkce_pair() -> PKCEPair:
    """Create an RFC 7636 S256 verifier/challenge pair."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return PKCEPair(verifier=verifier, challenge=challenge)


def parse_bearer_token(header_value: str | None) -> str | None:
    """Extract the credential from an ``Authorization`` header.

    Returns ``None`` when the header is absent or is not a well-formed single
    Bearer credential.
    """
    if not header_value:
        return None
    scheme, separator, credentials = header_value.partition(" ")
    if not separator or scheme.strip().lower() != "bearer":
        return None
    token = credentials.strip()
    if not token or " " in token:
        return None
    return token


# ---------------------------------------------------------------------------
# JWKS cache
# ---------------------------------------------------------------------------


class JWKSClient:
    """Async, ``kid``-keyed JWKS cache with a bounded refresh rate."""

    def __init__(
        self,
        uri: str,
        *,
        cache_ttl_seconds: int = 300,
        min_refresh_seconds: float = 5.0,
        timeout_seconds: float = 10.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if cache_ttl_seconds <= 0:
            raise ValueError("JWKS cache TTL must be positive")
        self._uri = uri
        self._ttl = float(cache_ttl_seconds)
        self._min_refresh = max(0.0, min_refresh_seconds)
        self._client = client or httpx.AsyncClient(
            timeout=timeout_seconds,
            follow_redirects=False,
            headers={"accept": "application/json"},
        )
        self._owns_client = client is None
        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched_at = 0.0
        self._last_attempt = 0.0
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str) -> dict[str, Any] | None:
        """Return the JWK for ``kid``, refreshing the cache when needed."""
        async with self._lock:
            now = time.monotonic()
            fresh = bool(self._keys) and (now - self._fetched_at) < self._ttl
            if fresh and kid in self._keys:
                return self._keys[kid]

            # Refresh when the cache is empty/stale, or once the rate limit has
            # elapsed for an unknown kid (key rotation without a restart).
            if (
                not fresh or kid not in self._keys
            ) and now - self._last_attempt >= self._min_refresh:
                self._last_attempt = now
                try:
                    await self._fetch()
                except JWKSFetchError:
                    # Serve a stale cache rather than fail every request.
                    if not self._keys:
                        raise
                    logger.warning("JWKS refresh failed; using the cached key set")

            return self._keys.get(kid)

    async def _fetch(self) -> None:
        try:
            response = await self._client.get(self._uri)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise JWKSFetchError("could not fetch the JWKS document") from exc

        if not isinstance(payload, dict):
            raise JWKSFetchError("JWKS document is not a JSON object")
        raw_keys = payload.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise JWKSFetchError("JWKS document contains no keys")

        keys: dict[str, dict[str, Any]] = {}
        for raw in raw_keys:
            if not isinstance(raw, dict):
                continue
            kid = raw.get("kid")
            if not isinstance(kid, str) or not kid:
                continue
            if raw.get("kty") != "RSA":
                continue
            if raw.get("alg") not in (None, _ALGORITHM):
                continue
            if raw.get("use") not in (None, "sig"):
                continue
            if not isinstance(raw.get("n"), str) or not isinstance(raw.get("e"), str):
                continue
            keys[kid] = raw

        if not keys:
            raise JWKSFetchError("JWKS document contains no usable RS256 signing keys")
        self._keys = keys
        self._fetched_at = time.monotonic()
        logger.debug("JWKS refreshed", extra={"keys": sorted(keys)})

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    @property
    def key_ids(self) -> frozenset[str]:
        """Currently cached key ids (diagnostics only)."""
        return frozenset(self._keys)


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------


class TokenValidator:
    """Validate RSA-signed access and ID tokens against a JWKS document."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        client_id: str,
        jwks: JWKSClient,
        leeway_seconds: int = 30,
    ) -> None:
        if not issuer:
            raise ValueError("issuer must not be empty")
        if not audience:
            raise ValueError("audience must not be empty")
        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._client_id = client_id
        self._jwks = jwks
        self._leeway = timedelta(seconds=max(0, leeway_seconds))

    async def validate_access_token(self, token: str) -> Principal:
        """Validate an RS256 access token and derive the caller's identity."""
        claims = await self._decode(
            token,
            audience=self._audience,
            required_claims=("exp", "iat", "sub"),
        )
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise TokenValidationError("missing_claim", "token has no subject")

        roles = _extract_roles(claims)
        username = _optional_str(claims.get("preferred_username"))
        email = _optional_str(claims.get("email"))
        return Principal(
            subject=subject,
            username=username,
            email=email,
            roles=roles,
            claims=claims,
        )

    async def validate_id_token(
        self,
        token: str,
        *,
        expected_nonce: str | None = None,
    ) -> dict[str, Any]:
        """Validate an ID token and, when supplied, its ``nonce`` binding."""
        claims = await self._decode(
            token,
            audience=self._client_id,
            required_claims=("exp", "iat", "sub"),
        )
        if expected_nonce is not None:
            nonce = claims.get("nonce")
            if not isinstance(nonce, str) or not secrets.compare_digest(nonce, expected_nonce):
                raise TokenValidationError("invalid_nonce", "ID token nonce mismatch")
        return claims

    async def _decode(
        self,
        token: str,
        *,
        audience: str,
        required_claims: tuple[str, ...],
    ) -> dict[str, Any]:
        if not isinstance(token, str):
            raise TokenValidationError("malformed_token")
        token = token.strip()
        if not token or len(token) > MAX_TOKEN_LENGTH:
            raise TokenValidationError("malformed_token")

        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError as exc:
            raise TokenValidationError("malformed_token") from exc

        if header.get("alg") != _ALGORITHM:
            # Deliberately before signature verification: never let the token
            # choose the algorithm that validates it.
            raise TokenValidationError("unsupported_algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenValidationError("malformed_token", "token has no key id")

        try:
            jwk = await self._jwks.get_key(kid)
        except JWKSFetchError as exc:
            raise TokenValidationError("jwks_unavailable") from exc
        if jwk is None:
            raise TokenValidationError("unknown_signing_key")

        try:
            public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
        except (ValueError, PyJWTError) as exc:
            raise TokenValidationError("jwks_invalid") from exc

        try:
            claims = jwt.decode(
                token,
                key=public_key,  # type: ignore[arg-type]
                algorithms=[_ALGORITHM],
                audience=audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={
                    "require": list(required_claims),
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except ExpiredSignatureError as exc:
            raise TokenValidationError("expired_token") from exc
        except InvalidAudienceError as exc:
            raise TokenValidationError("invalid_audience") from exc
        except InvalidIssuerError as exc:
            raise TokenValidationError("invalid_issuer") from exc
        except InvalidSignatureError as exc:
            raise TokenValidationError("invalid_signature") from exc
        except MissingRequiredClaimError as exc:
            raise TokenValidationError("missing_claim") from exc
        except InvalidAlgorithmError as exc:
            raise TokenValidationError("unsupported_algorithm") from exc
        except (DecodeError, PyJWTError) as exc:
            raise TokenValidationError("invalid_token") from exc

        if not isinstance(claims, dict):
            raise TokenValidationError("invalid_token")
        return claims


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _extract_roles(claims: dict[str, Any]) -> frozenset[str]:
    realm_access = claims.get("realm_access")
    if not isinstance(realm_access, dict):
        return frozenset()
    roles = realm_access.get("roles")
    if not isinstance(roles, list):
        return frozenset()
    return normalise_roles(roles)


# ---------------------------------------------------------------------------
# Token endpoint client (authorization-code + refresh grants)
# ---------------------------------------------------------------------------


class OIDCTokenClient:
    """Back-channel client for Keycloak's token endpoint."""

    def __init__(
        self,
        *,
        token_endpoint: str,
        authorization_endpoint: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: str = "openid profile email",
        timeout_seconds: float = 10.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._token_endpoint = token_endpoint
        self._authorization_endpoint = authorization_endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._scopes = scopes
        self._client = client or httpx.AsyncClient(
            timeout=timeout_seconds,
            follow_redirects=False,
            headers={"accept": "application/json"},
        )
        self._owns_client = client is None

    def authorization_url(
        self,
        *,
        state: str,
        nonce: str,
        code_challenge: str,
        prompt: str | None = None,
    ) -> str:
        """Build the browser-facing authorization request URL."""
        params: dict[str, str] = {
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "response_type": "code",
            "scope": self._scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if prompt:
            params["prompt"] = prompt
        return f"{self._authorization_endpoint}?{urllib.parse.urlencode(params)}"

    async def exchange_code(self, *, code: str, code_verifier: str) -> TokenSet:
        """Redeem an authorization code (confidential client + PKCE)."""
        return await self._request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._redirect_uri,
                "code_verifier": code_verifier,
            }
        )

    async def refresh(self, *, refresh_token: str) -> TokenSet:
        """Refresh an expired access token without another browser round-trip."""
        return await self._request(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }
        )

    async def _request(self, data: dict[str, str]) -> TokenSet:
        try:
            response = await self._client.post(
                self._token_endpoint,
                data=data,
                auth=httpx.BasicAuth(self._client_id, self._client_secret),
            )
        except httpx.HTTPError as exc:
            raise OAuthExchangeError("token_endpoint_unreachable") from exc

        if response.status_code >= 400:
            error, description = _token_error(response)
            raise OAuthExchangeError(error, description)

        try:
            payload = response.json()
        except ValueError as exc:
            raise OAuthExchangeError("invalid_response") from exc
        if not isinstance(payload, dict):
            raise OAuthExchangeError("invalid_response")

        access_token = payload.get("access_token")
        token_type = payload.get("token_type", "Bearer")
        expires_in = payload.get("expires_in", 300)
        if not isinstance(access_token, str) or not access_token:
            raise OAuthExchangeError("invalid_response", "missing access_token")
        if not isinstance(token_type, str):
            raise OAuthExchangeError("invalid_response", "invalid token_type")
        if not isinstance(expires_in, int | float) or expires_in <= 0:
            expires_in = 300

        return TokenSet(
            access_token=access_token,
            token_type=token_type,
            expires_in=int(expires_in),
            refresh_token=_optional_str(payload.get("refresh_token")),
            id_token=_optional_str(payload.get("id_token")),
            scope=_optional_str(payload.get("scope")),
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def _token_error(response: httpx.Response) -> tuple[str, str | None]:
    """Extract a Keycloak error code without ever logging token material."""
    try:
        payload = response.json()
    except ValueError:
        return "token_endpoint_error", None
    if not isinstance(payload, dict):
        return "token_endpoint_error", None
    error = payload.get("error")
    description = payload.get("error_description")
    return (
        error if isinstance(error, str) and error else "token_endpoint_error",
        description if isinstance(description, str) else None,
    )
