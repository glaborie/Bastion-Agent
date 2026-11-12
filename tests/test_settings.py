"""Configuration and secret-hygiene tests."""

from __future__ import annotations

import base64
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from settings import (
    CANARY_PREFIX_MIN_LENGTH,
    DEV_APPROVAL_HMAC_SECRET,
    DEV_JOB_SIGNING_SECRET,
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
    assert settings.canary_prefix == "BASTION-CANARY-"
    assert len(settings.canary_prefix) >= CANARY_PREFIX_MIN_LENGTH


@pytest.mark.parametrize("prefix", ["", "C", "CANARY-"])
def test_canary_prefix_must_be_at_least_eight_characters(prefix: str) -> None:
    with pytest.raises(ValidationError, match=r"CANARY_PREFIX must be at least 8"):
        make_settings(canary_prefix=prefix)


def test_canary_prefix_at_the_floor_is_accepted() -> None:
    prefix = "EIGHTCHR"
    assert len(prefix) == CANARY_PREFIX_MIN_LENGTH
    assert make_settings(canary_prefix=prefix).canary_prefix == prefix


def test_gpu_graph_digests_are_validated_like_the_cpu_ones() -> None:
    settings = make_settings()
    assert settings.classifier_injection_model_gpu_path is None
    assert settings.classifier_safety_model_gpu_sha256 is None
    assert settings.classifier_safety_unsafe_threshold_gpu is None
    assert settings.classifier_execution_provider == "cpu"

    digest = "a" * 64
    assert (
        make_settings(
            classifier_injection_model_gpu_path="models/injection/onnx/model.onnx",
            classifier_injection_model_gpu_sha256=digest,
        ).classifier_injection_model_gpu_sha256
        == digest
    )
    with pytest.raises(ValidationError, match="64 hexadecimal"):
        make_settings(classifier_safety_model_gpu_sha256="not-a-digest")
    # An empty value is "not pinned", not a malformed digest.
    blank = make_settings(classifier_safety_model_gpu_sha256="  ")
    assert blank.classifier_safety_model_gpu_sha256 is None

    # The fp32 operating point is a ratio like the int8 one.
    calibrated = make_settings(classifier_safety_unsafe_threshold_gpu=0.6)
    assert calibrated.classifier_safety_unsafe_threshold_gpu == 0.6
    with pytest.raises(ValidationError, match=r"within \[0\.0, 1\.0\]"):
        make_settings(classifier_safety_unsafe_threshold_gpu=1.5)


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

    with pytest.raises(ValidationError, match="JOB_SIGNING_SECRET"):
        make_settings(
            environment="production",
            vault_master_key=rotated_key,
            approval_hmac_secret="rotated-production-hmac-secret",
            job_signing_secret=DEV_JOB_SIGNING_SECRET,
        )

    with pytest.raises(ValidationError, match="KEYCLOAK_CLIENT_SECRET"):
        make_settings(
            environment="production",
            vault_master_key=rotated_key,
            approval_hmac_secret="rotated-production-hmac-secret",
            job_signing_secret="rotated-production-job-secret",
            session_cookie_secure=True,
        )

    with pytest.raises(ValidationError, match="SESSION_COOKIE_SECURE"):
        make_settings(
            environment="production",
            vault_master_key=rotated_key,
            approval_hmac_secret="rotated-production-hmac-secret",
            job_signing_secret="rotated-production-job-secret",
            keycloak_client_secret="rotated-production-client-secret",
        )

    hardened = make_settings(
        environment="production",
        vault_master_key=rotated_key,
        approval_hmac_secret="rotated-production-hmac-secret",
        job_signing_secret="rotated-production-job-secret",
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


def test_compose_dlp_entity_default_matches_settings() -> None:
    """A drift here silently re-enables the pre-IDEA-017 entity list in Docker.

    ``docker-compose.yml`` supplies ``DLP_ENTITIES`` as a container environment
    variable, and an environment variable wins over the Pydantic default. The
    live check for IDEA-017 hit exactly this: the image carried the new
    ``ADDRESS``/``DATE_OF_BIRTH`` recognizers but the compose default still
    narrowed the entity list, so neither fired.
    """
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    match = re.search(r"^  DLP_ENTITIES: \$\{DLP_ENTITIES:-([^}]+)\}$", compose, re.MULTILINE)
    assert match, "docker-compose.yml no longer defaults DLP_ENTITIES"
    compose_entities = tuple(match.group(1).split(","))
    assert compose_entities == make_settings().dlp_entity_list


def test_production_refuses_to_start_with_payload_escrow_enabled() -> None:
    production: dict[str, object] = {
        "environment": "production",
        "payload_escrow_enabled": True,
        "vault_master_key": base64.b64encode(b"p" * 32).decode(),
        "approval_hmac_secret": "rotated-production-approval-secret",
        "job_signing_secret": "rotated-production-job-secret",
        "keycloak_client_secret": "rotated-production-keycloak-secret",
        "session_cookie_secure": True,
    }
    with pytest.raises(ValidationError, match="PAYLOAD_ESCROW_ENABLED"):
        make_settings(**production)

    # The same production-valid secrets pass with the flag off, so the failure
    # above is the escrow guard, not the dev-secret guard.
    allowed = make_settings(**{**production, "payload_escrow_enabled": False})
    assert allowed.environment == "production"
    assert allowed.payload_escrow_enabled is False


def test_payload_escrow_defaults_and_key_derivation() -> None:
    settings = make_settings()
    assert settings.payload_escrow_enabled is False
    assert settings.payload_escrow_ttl_seconds == 86_400
    assert len(settings.payload_escrow_key_bytes) == 32
    # A labelled subkey, never the vault key itself.
    assert settings.payload_escrow_key_bytes != settings.vault_key_bytes

    dedicated = base64.b64encode(b"e" * 32).decode()
    explicit = make_settings(payload_escrow_master_key=dedicated)
    assert explicit.payload_escrow_key_bytes == b"e" * 32

    with pytest.raises(ValidationError, match="PAYLOAD_ESCROW_MASTER_KEY"):
        make_settings(payload_escrow_master_key="too-short")

    env_example = Path(".env.example").read_text(encoding="utf-8")
    assert "\nPAYLOAD_ESCROW_ENABLED=false\n" in env_example
    assert "pre-production" in env_example
    assert "\nPAYLOAD_ESCROW_MASTER_KEY=\n" in env_example


def test_compose_forwards_payload_escrow_settings() -> None:
    """The container must not silently ignore the flag set in ``.env``."""
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    for variable in (
        "PAYLOAD_ESCROW_ENABLED",
        "PAYLOAD_ESCROW_TTL_SECONDS",
        "PAYLOAD_ESCROW_MASTER_KEY",
        "RESPONSE_STORE_MAX_CHARS",
    ):
        assert re.search(rf"^  {variable}: \$\{{{variable}:-", compose, re.MULTILINE), (
            f"docker-compose.yml does not forward {variable}"
        )


def test_response_store_cap_is_positive_and_documented() -> None:
    settings = make_settings()
    assert settings.response_store_max_chars == 32_768
    with pytest.raises(ValidationError, match="positive integer"):
        make_settings(response_store_max_chars=0)

    env_example = Path(".env.example").read_text(encoding="utf-8")
    assert "\nRESPONSE_STORE_MAX_CHARS=32768\n" in env_example
    assert "truncated=true" in env_example


def test_audit_event_vocabulary_ddl_covers_every_event_type() -> None:
    """The upgrade DDLs and the enums must not drift apart."""
    from db.models import (
        AUDIT_EVENT_VOCABULARY_DDL,
        ESCROW_KIND_DDL,
        AuditEventType,
        EscrowKind,
    )

    ddl = AUDIT_EVENT_VOCABULARY_DDL[0]
    for member in AuditEventType:
        assert f"'{member.value}'" in ddl, f"{member.name} is missing from the DDL"
    # The idempotence guard looks for the newest member so a database upgraded
    # before that member existed is rewritten. Appending a member therefore means
    # updating both the IN list and this marker.
    newest = list(AuditEventType)[-1].value
    assert f"LIKE '%{newest}%'" in ddl

    kind_ddl = ESCROW_KIND_DDL[0]
    for member in EscrowKind:
        assert f"'{member.value}'" in kind_ddl, f"{member.name} is missing from the DDL"
    newest_kind = list(EscrowKind)[-1].value
    assert f"LIKE '%{newest_kind}%'" in kind_ddl
