"""Centralised, 12-factor runtime configuration for Bastion-Agent.

Every setting is sourced from the process environment (or a local ``.env``
file during development). Secrets are wrapped in :class:`pydantic.SecretStr`
so they never leak through ``repr()``, structured logs, or tracebacks.
"""

from __future__ import annotations

import base64
import binascii
import functools
from typing import Literal
from urllib.parse import quote

from pydantic import SecretStr, computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Deterministic, openly-documented development key. Production deployments are
#: rejected at startup if these values are still in place (see ``_reject_dev_secrets``).
DEV_VAULT_MASTER_KEY = "YmFzdGlvbi1kZXYtaW5zZWN1cmUtdmF1bHQta2V5ISE="
DEV_APPROVAL_HMAC_SECRET = "dev-only-approval-hmac-secret-change-me"
DEV_KEYCLOAK_CLIENT_SECRET = "dev-only-keycloak-client-secret"

Environment = Literal["local", "ci", "staging", "production"]


class Settings(BaseSettings):
    """Typed view over the process environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -- Application -------------------------------------------------------
    app_name: str = "bastion-agent"
    environment: Environment = "local"
    log_level: str = "INFO"

    # -- PostgreSQL --------------------------------------------------------
    database_url: str = (
        "postgresql+asyncpg://bastion:dev-only-postgres-password@localhost:5432/bastion"
    )
    database_pool_size: int = 10
    database_max_overflow: int = 5
    database_pool_recycle_seconds: int = 1800
    database_connect_timeout_seconds: float = 10.0
    database_echo: bool = False

    # -- Redis -------------------------------------------------------------
    redis_url: str = "redis://:dev-only-redis-password@localhost:6379/0"
    redis_max_connections: int = 50

    # -- Keycloak / OIDC ---------------------------------------------------
    keycloak_issuer: str = "http://localhost:8080/realms/bastion"
    keycloak_audience: str = "bastion-gateway"
    keycloak_client_id: str = "bastion-gateway"
    keycloak_client_secret: SecretStr = SecretStr(DEV_KEYCLOAK_CLIENT_SECRET)
    #: Browser-facing callback registered on the Keycloak client.
    keycloak_redirect_uri: str = "http://localhost:8000/auth/callback"
    #: Endpoints default to the conventional paths under ``keycloak_issuer``.
    #: The token endpoint is separately overridable because the gateway reaches
    #: Keycloak over the internal network while the browser uses the public URL.
    keycloak_authorization_uri: str | None = None
    keycloak_token_uri: str | None = None
    keycloak_end_session_uri: str | None = None
    keycloak_scopes: str = "openid profile email"
    keycloak_jwks_uri: str | None = None
    keycloak_jwks_cache_ttl_seconds: int = 300
    keycloak_jwks_min_refresh_seconds: float = 5.0
    keycloak_leeway_seconds: int = 30
    keycloak_http_timeout_seconds: float = 10.0

    # -- Dashboard sessions (server-side, Redis-backed) --------------------
    session_cookie_name: str = "bastion_session"
    session_ttl_seconds: int = 28800  # 8 hours, sliding
    session_refresh_leeway_seconds: int = 60
    session_cookie_secure: bool = False  # local stack is plain HTTP on loopback
    login_state_ttl_seconds: int = 600
    #: Cookie set while a logout is in flight. `/auth/login` sees it and adds
    #: `prompt=login`, so a racing dashboard poll cannot silently re-use the
    #: Keycloak SSO session before RP-initiated logout completes.
    logout_marker_cookie_name: str = "bastion_logged_out"
    logout_marker_ttl_seconds: int = 120
    #: TTL for the one-time end-session URL handed to `/auth/logged-out`.
    logout_target_ttl_seconds: int = 120
    audit_page_size: int = 50
    approval_page_size: int = 100

    # -- Evaluation reports ------------------------------------------------
    #: JSON summary written by the DeepEval harness (Milestone 6).
    eval_report_path: str = "artifacts/evals/latest.json"

    # -- DLP: reversible token vault --------------------------------------
    vault_master_key: SecretStr = SecretStr(DEV_VAULT_MASTER_KEY)
    vault_ttl_seconds: int = 1800  # 30 minutes, per specification

    # -- Two-stage classifier ---------------------------------------------
    classifier_model_path: str | None = None
    #: Minimum confidence for the CONFIDENTIAL label. Prompts at or above it are
    #: routed to local inference; borderline results are deliberately treated as
    #: PUBLIC (cloud-primary) to reserve scarce GPU capacity — the threshold is
    #: the control point for that cost trade-off.
    classifier_confidence_threshold: float = 0.55

    # -- HITL approvals ----------------------------------------------------
    approval_hmac_secret: SecretStr = SecretStr(DEV_APPROVAL_HMAC_SECRET)
    approval_ttl_seconds: int = 900

    # -- OmniRoute inference router ---------------------------------------
    omniroute_base_url: str = "http://localhost:20128"
    omniroute_api_key: SecretStr = SecretStr("sk-local-dev")
    omniroute_timeout_seconds: float = 120.0
    model_local_alias: str = "local-llama"
    model_cloud_alias: str = "cloud-primary"

    # -- Observability -----------------------------------------------------
    otel_enabled: bool = True
    otel_service_name: str = "bastion-gateway"
    otel_exporter_otlp_endpoint: str = "http://localhost:4318"
    otel_traces_sampler_ratio: float = 1.0

    # -- Egress sanitizer --------------------------------------------------
    canary_prefix: str = "CANARY-"

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    @field_validator(
        "keycloak_jwks_uri",
        "keycloak_authorization_uri",
        "keycloak_token_uri",
        "keycloak_end_session_uri",
        "classifier_model_path",
        mode="before",
    )
    @classmethod
    def _blank_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("vault_master_key")
    @classmethod
    def _validate_vault_master_key(cls, value: SecretStr) -> SecretStr:
        try:
            raw = base64.b64decode(value.get_secret_value(), validate=True)
        except (binascii.Error, ValueError) as exc:  # pragma: no cover - defensive
            raise ValueError("VAULT_MASTER_KEY must be valid base64") from exc
        if len(raw) != 32:
            raise ValueError(
                f"VAULT_MASTER_KEY must decode to exactly 32 bytes (AES-256); got {len(raw)}"
            )
        return value

    @field_validator("otel_traces_sampler_ratio", "classifier_confidence_threshold")
    @classmethod
    def _validate_ratio(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("value must be within [0.0, 1.0]")
        return value

    @field_validator(
        "session_ttl_seconds",
        "login_state_ttl_seconds",
        "logout_marker_ttl_seconds",
        "logout_target_ttl_seconds",
        "audit_page_size",
        "approval_page_size",
        "keycloak_jwks_cache_ttl_seconds",
    )
    @classmethod
    def _validate_positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("value must be a positive integer")
        return value

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        level = value.upper()
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        if level not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(allowed)}")
        return level

    @model_validator(mode="after")
    def _reject_dev_secrets(self) -> Settings:
        if self.environment not in {"staging", "production"}:
            return self
        if self.vault_master_key.get_secret_value() == DEV_VAULT_MASTER_KEY:
            raise ValueError("VAULT_MASTER_KEY must be rotated before non-local deployment")
        if self.approval_hmac_secret.get_secret_value() == DEV_APPROVAL_HMAC_SECRET:
            raise ValueError("APPROVAL_HMAC_SECRET must be rotated before non-local deployment")
        if self.keycloak_client_secret.get_secret_value() == DEV_KEYCLOAK_CLIENT_SECRET:
            raise ValueError("KEYCLOAK_CLIENT_SECRET must be rotated before non-local deployment")
        if not self.session_cookie_secure:
            raise ValueError("SESSION_COOKIE_SECURE must be enabled outside local development")
        return self

    # ------------------------------------------------------------------
    # Derived values
    # ------------------------------------------------------------------
    @computed_field  # type: ignore[prop-decorator]
    @property
    def keycloak_jwks_url(self) -> str:
        """JWKS endpoint, derived from the issuer realm when not set explicitly."""
        if self.keycloak_jwks_uri:
            return self.keycloak_jwks_uri
        return f"{self.keycloak_issuer.rstrip('/')}/protocol/openid-connect/certs"

    @property
    def keycloak_authorization_endpoint(self) -> str:
        """Browser-facing authorization endpoint."""
        if self.keycloak_authorization_uri:
            return self.keycloak_authorization_uri
        return f"{self.keycloak_issuer.rstrip('/')}/protocol/openid-connect/auth"

    @property
    def keycloak_token_endpoint(self) -> str:
        """Back-channel token endpoint (internal URL in Compose)."""
        if self.keycloak_token_uri:
            return self.keycloak_token_uri
        return f"{self.keycloak_issuer.rstrip('/')}/protocol/openid-connect/token"

    @property
    def keycloak_end_session_endpoint(self) -> str:
        """Browser-facing RP-initiated logout endpoint."""
        if self.keycloak_end_session_uri:
            return self.keycloak_end_session_uri
        return f"{self.keycloak_issuer.rstrip('/')}/protocol/openid-connect/logout"

    @property
    def vault_key_bytes(self) -> bytes:
        """The 32-byte AES-256 key backing the reversible token vault."""
        return base64.b64decode(self.vault_master_key.get_secret_value())

    @property
    def redacted_database_url(self) -> str:
        """Database URL with the password masked, safe for logs."""
        _, _, tail = self.database_url.partition("://")
        credentials, sep, host = tail.rpartition("@")
        if not sep:
            return self.database_url
        user, _, _password = credentials.partition(":")
        return f"postgresql+asyncpg://{quote(user)}:***@{host}"


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()


def reset_settings_cache() -> None:
    """Drop the cached settings (used by tests and after secret rotation)."""
    get_settings.cache_clear()
