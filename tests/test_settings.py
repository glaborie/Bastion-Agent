"""Configuration and secret-hygiene tests."""

from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError

from settings import (
    DEV_APPROVAL_HMAC_SECRET,
    DEV_VAULT_MASTER_KEY,
    Settings,
)


def make_settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def test_defaults_are_valid_for_local_development() -> None:
    settings = make_settings()
    assert settings.environment == "local"
    assert len(settings.vault_key_bytes) == 32
    assert settings.vault_ttl_seconds == 1800
    assert settings.approval_ttl_seconds == 900


def test_vault_key_must_decode_to_32_bytes() -> None:
    short_key = base64.b64encode(b"sixteen-byte-key").decode()
    with pytest.raises(ValidationError, match="exactly 32 bytes"):
        make_settings(vault_master_key=short_key)

    with pytest.raises(ValidationError, match="base64"):
        make_settings(vault_master_key="not base64!!")


def test_production_rejects_development_secrets() -> None:
    with pytest.raises(ValidationError, match="VAULT_MASTER_KEY"):
        make_settings(environment="production")

    rotated_key = base64.b64encode(b"z" * 32).decode()
    with pytest.raises(ValidationError, match="APPROVAL_HMAC_SECRET"):
        make_settings(
            environment="production",
            vault_master_key=rotated_key,
            approval_hmac_secret=DEV_APPROVAL_HMAC_SECRET,
        )

    with pytest.raises(ValidationError, match="KEYCLOAK_CLIENT_SECRET"):
        make_settings(
            environment="production",
            vault_master_key=rotated_key,
            approval_hmac_secret="rotated-production-hmac-secret",
            session_cookie_secure=True,
        )

    with pytest.raises(ValidationError, match="SESSION_COOKIE_SECURE"):
        make_settings(
            environment="production",
            vault_master_key=rotated_key,
            approval_hmac_secret="rotated-production-hmac-secret",
            keycloak_client_secret="rotated-production-client-secret",
        )

    hardened = make_settings(
        environment="production",
        vault_master_key=rotated_key,
        approval_hmac_secret="rotated-production-hmac-secret",
        keycloak_client_secret="rotated-production-client-secret",
        session_cookie_secure=True,
    )
    assert hardened.environment == "production"


def test_jwks_url_is_derived_from_the_issuer() -> None:
    settings = make_settings(keycloak_jwks_uri=None)
    assert settings.keycloak_jwks_url == (
        f"{settings.keycloak_issuer}/protocol/openid-connect/certs"
    )

    explicit = make_settings(keycloak_jwks_uri="http://keycloak:8080/realms/bastion/certs")
    assert explicit.keycloak_jwks_url == "http://keycloak:8080/realms/bastion/certs"


def test_database_url_is_redacted_for_logs() -> None:
    settings = make_settings(
        database_url="postgresql+asyncpg://bastion:super-secret@db:5432/bastion"
    )
    assert "super-secret" not in settings.redacted_database_url
    assert "bastion:***@db:5432/bastion" in settings.redacted_database_url


def test_dev_vault_key_constant_is_a_valid_aes256_key() -> None:
    assert len(base64.b64decode(DEV_VAULT_MASTER_KEY)) == 32
