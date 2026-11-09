"""OIDC/JWKS validation tests (ADR-001)."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from gateway.auth.oidc import (
    JWKSClient,
    TokenValidationError,
    TokenValidator,
    generate_pkce_pair,
    parse_bearer_token,
)

ISSUER = "http://localhost:8080/realms/bastion"
AUDIENCE = "bastion-gateway"
CLIENT_ID = "bastion-gateway"
KID = "test-key-1"

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


_PUBLIC_NUMBERS = _PRIVATE_KEY.public_key().public_numbers()
JWK: dict[str, Any] = {
    "kty": "RSA",
    "kid": KID,
    "use": "sig",
    "alg": "RS256",
    "n": _b64_uint(_PUBLIC_NUMBERS.n),
    "e": _b64_uint(_PUBLIC_NUMBERS.e),
}


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-123",
        "iat": now - 10,
        "exp": now + 300,
        "preferred_username": "alice",
        "email": "alice@bastion.local",
        "realm_access": {"roles": ["operator", "offline_access", "default-roles-bastion"]},
    }
    base.update(overrides)
    return base


def sign(payload: dict[str, Any], *, kid: str = KID) -> str:
    return jwt.encode(payload, _PRIVATE_KEY, algorithm="RS256", headers={"kid": kid})


def build_validator(
    *,
    handler: httpx.MockTransport | None = None,
    min_refresh_seconds: float = 5.0,
) -> tuple[TokenValidator, httpx.AsyncClient, dict[str, int]]:
    attempts = {"count": 0}

    def default_handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        return httpx.Response(200, json={"keys": [JWK]})

    transport = handler or httpx.MockTransport(default_handler)
    client = httpx.AsyncClient(transport=transport)
    jwks = JWKSClient(
        "https://idp.test/certs",
        client=client,
        min_refresh_seconds=min_refresh_seconds,
    )
    validator = TokenValidator(
        issuer=ISSUER,
        audience=AUDIENCE,
        client_id=CLIENT_ID,
        jwks=jwks,
    )
    return validator, client, attempts


def _code(exception_info: pytest.ExceptionInfo[TokenValidationError]) -> str:
    return exception_info.value.code


async def test_valid_token_yields_principal_and_known_roles() -> None:
    validator, client, _ = build_validator()
    try:
        principal = await validator.validate_access_token(sign(claims()))
    finally:
        await client.aclose()

    assert principal.subject == "user-123"
    assert principal.username == "alice"
    assert principal.email == "alice@bastion.local"
    assert principal.roles == frozenset({"operator"})
    assert principal.display_name == "alice"


async def test_unknown_realm_roles_are_dropped() -> None:
    validator, client, _ = build_validator()
    try:
        principal = await validator.validate_access_token(
            sign(claims(realm_access={"roles": ["uma_authorization", "analyst"]}))
        )
    finally:
        await client.aclose()
    assert principal.roles == frozenset({"analyst"})


async def test_missing_roles_claim_is_empty_not_an_error() -> None:
    validator, client, _ = build_validator()
    try:
        principal = await validator.validate_access_token(sign(claims(realm_access=None)))
    finally:
        await client.aclose()
    assert principal.roles == frozenset()


async def test_expired_token_is_rejected() -> None:
    validator, client, _ = build_validator()
    expired = claims(exp=int(time.time()) - 120, iat=int(time.time()) - 400)
    try:
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_access_token(sign(expired))
    finally:
        await client.aclose()
    assert _code(info) == "expired_token"


async def test_wrong_audience_is_rejected() -> None:
    validator, client, _ = build_validator()
    try:
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_access_token(sign(claims(aud="another-service")))
    finally:
        await client.aclose()
    assert _code(info) == "invalid_audience"


async def test_wrong_issuer_is_rejected() -> None:
    validator, client, _ = build_validator()
    try:
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_access_token(
                sign(claims(iss="http://evil.example/realms/bastion"))
            )
    finally:
        await client.aclose()
    assert _code(info) == "invalid_issuer"


async def test_tampered_signature_is_rejected() -> None:
    validator, client, _ = build_validator()
    token = sign(claims())
    header, payload, signature = token.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    decoded["sub"] = "mallory"
    replaced = base64.urlsafe_b64encode(json.dumps(decoded).encode()).rstrip(b"=").decode()
    tampered = f"{header}.{replaced}.{signature}"
    try:
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_access_token(tampered)
    finally:
        await client.aclose()
    assert _code(info) == "invalid_signature"


async def test_alg_none_is_rejected_before_any_key_lookup() -> None:
    validator, client, attempts = build_validator()

    def encode(payload: dict[str, Any]) -> str:
        header = {"alg": "none", "typ": "JWT", "kid": KID}
        parts = []
        for item in (header, payload):
            raw = json.dumps(item).encode()
            parts.append(base64.urlsafe_b64encode(raw).rstrip(b"=").decode())
        return ".".join(parts) + "."

    try:
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_access_token(encode(claims()))
    finally:
        await client.aclose()
    assert _code(info) == "unsupported_algorithm"
    assert attempts["count"] == 0


async def test_hmac_token_with_rsa_kid_is_rejected() -> None:
    validator, client, _ = build_validator()
    token = jwt.encode(claims(), "x" * 32, algorithm="HS256", headers={"kid": KID})
    try:
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_access_token(token)
    finally:
        await client.aclose()
    assert _code(info) == "unsupported_algorithm"


async def test_missing_required_claim_is_rejected() -> None:
    validator, client, _ = build_validator()
    payload = claims()
    payload.pop("iat")
    try:
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_access_token(sign(payload))
    finally:
        await client.aclose()
    assert _code(info) == "missing_claim"


async def test_unknown_kid_refreshes_once_then_rejects() -> None:
    validator, client, attempts = build_validator(min_refresh_seconds=0)
    try:
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_access_token(sign(claims(), kid="rotated-key"))
        first_attempts = attempts["count"]
        with pytest.raises(TokenValidationError):
            await validator.validate_access_token(sign(claims(), kid="rotated-key"))
        second_attempts = attempts["count"]
    finally:
        await client.aclose()
    assert _code(info) == "unknown_signing_key"
    assert first_attempts == 1
    assert second_attempts == 2


async def test_unknown_kid_does_not_refetch_inside_the_rate_limit() -> None:
    validator, client, attempts = build_validator(min_refresh_seconds=300)
    try:
        await validator.validate_access_token(sign(claims()))
        with pytest.raises(TokenValidationError):
            await validator.validate_access_token(sign(claims(), kid="rotated-key"))
        with pytest.raises(TokenValidationError):
            await validator.validate_access_token(sign(claims(), kid="rotated-key"))
    finally:
        await client.aclose()
    assert attempts["count"] == 1


async def test_jwks_outage_without_cache_is_reported() -> None:
    def failing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "unavailable"})

    validator, client, _ = build_validator(handler=httpx.MockTransport(failing))
    try:
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_access_token(sign(claims()))
    finally:
        await client.aclose()
    assert _code(info) == "jwks_unavailable"


async def test_token_without_kid_is_rejected() -> None:
    validator, client, _ = build_validator()
    token = jwt.encode(claims(), _PRIVATE_KEY, algorithm="RS256")
    try:
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_access_token(token)
    finally:
        await client.aclose()
    assert _code(info) == "malformed_token"


async def test_id_token_nonce_binding() -> None:
    validator, client, _ = build_validator()
    token = sign(claims(aud=CLIENT_ID, nonce="expected-nonce"))
    try:
        await validator.validate_id_token(token, expected_nonce="expected-nonce")
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_id_token(token, expected_nonce="other-nonce")
    finally:
        await client.aclose()
    assert _code(info) == "invalid_nonce"


def test_pkce_challenge_is_s256_of_the_verifier() -> None:
    import hashlib

    pair = generate_pkce_pair()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(pair.verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert pair.challenge == expected
    assert 43 <= len(pair.verifier) <= 128


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, None),
        ("", None),
        ("Bearer ", None),
        ("Basic abc", None),
        ("Bearer abc def", None),
        ("Bearer token-123", "token-123"),
        ("bearer token-123", "token-123"),
    ],
)
def test_bearer_parsing(header: str | None, expected: str | None) -> None:
    assert parse_bearer_token(header) == expected
