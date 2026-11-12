"""Centralised, 12-factor runtime configuration for Bastion-Agent.

Every setting is sourced from the process environment (or a local ``.env``
file during development). Secrets are wrapped in :class:`pydantic.SecretStr`
so they never leak through ``repr()``, structured logs, or tracebacks.
"""

from __future__ import annotations

import base64
import binascii
import functools
from typing import Final, Literal
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import SecretStr, computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Deterministic, openly-documented development key. Production deployments are
#: rejected at startup if these values are still in place (see ``_reject_dev_secrets``).
DEV_VAULT_MASTER_KEY = "YmFzdGlvbi1kZXYtaW5zZWN1cmUtdmF1bHQta2V5ISE="
DEV_APPROVAL_HMAC_SECRET = "dev-only-approval-hmac-secret-change-me"
DEV_JOB_SIGNING_SECRET = "dev-only-job-signing-secret-change-me"
DEV_KEYCLOAK_CLIENT_SECRET = "dev-only-keycloak-client-secret"
DEV_AUDIT_WITNESS_HMAC_SECRET = "dev-only-audit-witness-hmac-secret-change-me"

Environment = Literal["local", "ci", "staging", "production"]

#: Minimum length of ``CANARY_PREFIX``. ``inspect()`` blocks any output that
#: matches the configured prefix, so a short marker would quarantine ordinary
#: text; the floor is enforced at startup rather than at the first request.
CANARY_PREFIX_MIN_LENGTH: Final[int] = 8


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

    # -- East-west TLS (ADR-019) -------------------------------------------
    #: PostgreSQL transport. ``disable`` is the local default and the only mode
    #: the default compose profile uses; the ``pki`` profile sets
    #: ``verify-full`` so a password alone cannot reach the database.
    database_ssl_mode: Literal["disable", "require", "verify-ca", "verify-full"] = "disable"
    #: Redis transport. When set, the client requires a server certificate
    #: signed by ``pki_ca_cert_path`` and presents its own client certificate.
    redis_tls_enabled: bool = False
    #: CA bundle every east-west client trusts. Read at engine/client creation,
    #: so a missing file fails closed instead of falling back to plaintext.
    pki_ca_cert_path: str = "/pki/ca/ca.crt"
    #: Client certificate and key this process presents. Distinct per service
    #: so a compromised workload holds only its own private key.
    pki_client_cert_path: str = "/pki/client/tls.crt"
    pki_client_key_path: str = "/pki/client/tls.key"
    #: CA bundle the gateway trusts when it calls Keycloak over HTTPS. Empty
    #: means the system store, which is the local plaintext default; the
    #: ``pki`` profile points it at the internal CA.
    oidc_ca_cert_path: str = ""

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
    #: Access-token claim carrying the tenant. The Keycloak realm maps the
    #: ``tenant`` user attribute to this claim; a token without it is rejected
    #: rather than falling back to a shared namespace (ADR-015).
    tenant_claim: str = "tenant_id"

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

    # -- Audit witness (ADR-005 decision 9) --------------------------------
    #: Opt-in external anchor of the audit chain head. The `compliance` compose
    #: profile supplies MinIO with a versioned bucket under COMPLIANCE object
    #: lock; `scripts/write_audit_witness.py` stores one signed witness per run.
    #: Leaving the credentials unset disables the feature; verification then
    #: reports "could not verify" rather than passing.
    audit_witness_endpoint: str = "http://localhost:9000"
    audit_witness_bucket: str = "bastion-audit"
    audit_witness_region: str = "us-east-1"
    audit_witness_access_key: SecretStr | None = None
    audit_witness_secret_key: SecretStr | None = None
    #: Dedicated HMAC key. Keeping it separate from APPROVAL_HMAC_SECRET means
    #: rotating the four-eyes token secret does not invalidate stored witnesses.
    audit_witness_hmac_secret: SecretStr = SecretStr(DEV_AUDIT_WITNESS_HMAC_SECRET)
    #: Server-enforced object-lock retention. COMPLIANCE mode cannot be
    #: shortened once written, so change this before the first witness exists.
    audit_witness_retention_years: int = 7

    # -- Evaluation reports ------------------------------------------------
    #: JSON summary written by the DeepEval harness (Milestone 6).
    eval_report_path: str = "artifacts/evals/latest.json"

    # -- Per-principal rate limiting (ADR-013) -----------------------------
    #: A limiter outage is a 503, never an unlimited route: Redis already holds
    #: the vault and the canary registry, so it is already on the chat path.
    rate_limit_enabled: bool = True
    rate_limit_window_seconds: int = 60
    #: Dashboard pages, HTMX fragments and the JSON APIs they poll share one
    #: bucket per principal. Chat gets its own, larger budget because one turn
    #: is deliberate operator work rather than a background poll.
    rate_limit_dashboard_per_window: int = 60
    rate_limit_chat_per_window: int = 120

    # -- DLP: reversible token vault --------------------------------------
    vault_master_key: SecretStr = SecretStr(DEV_VAULT_MASTER_KEY)
    vault_ttl_seconds: int = 1800  # 30 minutes, per specification
    #: Presidio entity types to detect. API_KEY, ADDRESS, DATE_OF_BIRTH and
    #: AHV_NUMBER are local recognizers because Presidio ships no default for
    #: provider tokens, postal addresses, birth dates or the Swiss AHV/AVS
    #: number, and its LOCATION/DATE_TIME are too noisy to redact (see ADR-002).
    dlp_entities: str = (
        "PERSON,EMAIL_ADDRESS,PHONE_NUMBER,IBAN_CODE,IP_ADDRESS,CREDIT_CARD,US_SSN,"
        "API_KEY,ADDRESS,DATE_OF_BIRTH,AHV_NUMBER"
    )
    #: Presidio confidence floor. Lower values catch more edge cases but
    #: over-redact; this is not the confidentiality routing threshold.
    dlp_score_threshold: float = 0.35
    #: Language detector probability a non-English prompt must clear before the
    #: NER-backed entities are skipped. Below it the text is analyzed as
    #: English, so short English prompts keep full NER coverage (ADR-002).
    dlp_language_min_confidence: float = 0.8

    # -- Payload escrow (ADR-005 decision 7) -------------------------------
    #: Pre-production debugging only. When on, ``INPUT_RECEIVED`` also writes an
    #: AES-256-GCM copy of the exact payload it hashed to the separate
    #: ``payload_escrow`` table, readable only by an ``admin``. The flag defaults
    #: off and production refuses to start with it on; the ledger, its hashes and
    #: the chain are untouched either way.
    payload_escrow_enabled: bool = False
    #: Escrow retention. Deliberately far shorter than the ledger's multi-year
    #: retention (ADR-005 decision 5) because this table is a recoverable PII
    #: store, not the ledger.
    payload_escrow_ttl_seconds: int = 86_400  # 24 hours
    #: Dedicated 32-byte base64 key. When unset, a subkey is derived from
    #: ``VAULT_MASTER_KEY`` with HKDF-SHA256, so escrow needs no extra secret and
    #: no key material is committed.
    payload_escrow_master_key: SecretStr | None = None
    #: Maximum characters of the delivered answer covered by the ``RESPONSE_SENT``
    #: hash and its ``egress_delivered`` escrow copy. A longer answer is stored
    #: and hashed as its prefix with ``truncated: true`` in the event metadata, so
    #: an uncapped model hallucination cannot grow the ledger without bound.
    response_store_max_chars: int = 32_768

    # -- Two-stage classifier ---------------------------------------------
    #: Legacy single-graph contract: one ONNX file returning two logits ordered
    #: ``[PUBLIC, CONFIDENTIAL]``. It remains supported for a custom model, but
    #: it cannot detect prompt injection. Set the two ensemble paths below to
    #: use the ADR-011 gate instead.
    classifier_model_path: str | None = None
    #: Path to the Hugging Face ``tokenizer.json`` for the ONNX model. When
    #: unset, it is derived from the model directory. Ignored by the semantic
    #: rule fallback.
    classifier_tokenizer_path: str | None = None
    classifier_max_tokens: int = 512
    #: Minimum confidence for the CONFIDENTIAL label. Prompts at or above it are
    #: routed to local inference; borderline results are deliberately treated as
    #: PUBLIC (cloud-primary) to reserve scarce GPU capacity — the threshold is
    #: the control point for that cost trade-off.
    classifier_confidence_threshold: float = 0.55

    # -- Two-model ensemble (ADR-011) -------------------------------------
    #: Both paths must be set to enable the ensemble. Each points at the int8
    #: ONNX graph; its tokenizer is derived from the model directory when the
    #: matching ``*_tokenizer_path`` is empty.
    classifier_injection_model_path: str | None = None
    classifier_injection_tokenizer_path: str | None = None
    classifier_safety_model_path: str | None = None
    classifier_safety_tokenizer_path: str | None = None
    #: Token window per inference. The injection guard is trained for long
    #: documents and is windowed (max over windows) at 2048 tokens; the safety
    #: guard is prompt-sized at 512.
    classifier_injection_max_tokens: int = 2048
    classifier_safety_max_tokens: int = 512
    #: ``recall-first`` lowers the injection threshold from 0.662 to 0.5. It
    #: trades false alarms on benign text for recall and is intended for
    #: high-risk tenants and offline scanning, not as the default gate.
    classifier_injection_profile: Literal["production", "recall-first"] = "production"
    #: Explicit override for the injection threshold. Leave empty to take the
    #: value implied by ``classifier_injection_profile``.
    classifier_injection_threshold: float | None = None
    #: ``unsafe >= 0.5`` flags the prompt for review (ADR-011).
    classifier_safety_unsafe_threshold: float = 0.5
    #: Operating point for the fp32 GPU graph, calibrated separately: the fp32
    #: graph scores the benign prompt-engineering explainer 0.570 against the
    #: int8 graph's 0.364, so the CPU value would add a benign false positive.
    #: Empty means "use the CPU value"; the setting is ignored unless the CUDA
    #: session selected a configured GPU graph.
    classifier_safety_unsafe_threshold_gpu: float | None = None
    #: ``privacy``, ``fraud_manipulation``, ``criminal_planning`` and
    #: ``unauthorized_advice`` at or above this route CONFIDENTIAL.
    classifier_safety_category_threshold: float = 0.3
    #: Optional SHA-256 digests. When set, startup verifies the graph bytes so an
    #: operator cannot silently run a different quantisation.
    classifier_injection_model_sha256: str | None = None
    classifier_safety_model_sha256: str | None = None
    #: Full-precision graphs used when the resolved provider is CUDA. The int8
    #: graphs above keep the CPU path fast; the fp32 graphs are the only ones
    #: with real CUDA kernels, so they replace the int8 graphs on the device
    #: (ADR-011, measured 2026-11-11). Leave empty to run the configured graph
    #: on CUDA anyway (slower, but functional).
    classifier_injection_model_gpu_path: str | None = None
    classifier_safety_model_gpu_path: str | None = None
    #: Digests for the GPU graphs. Verified with the same contract as the CPU
    #: digests when the GPU path is selected.
    classifier_injection_model_gpu_sha256: str | None = None
    classifier_safety_model_gpu_sha256: str | None = None
    #: Keep the deterministic rule classifier as a floor when the ensemble is
    #: active. The safety model detects harmful content, not corporate
    #: confidentiality markings ("strictly confidential", board minutes,
    #: compensation), so disabling this lets explicitly marked material take the
    #: cloud path. It can only add CONFIDENTIAL decisions, never remove one.
    classifier_rules_floor: bool = True
    #: Execution provider for the ensemble graphs. ``cpu`` is the default
    #: because the shipped int8 graphs are measurably *faster* on the CPU: the
    #: quantised matmuls have no CUDA kernel and shuttle their tensors over
    #: PCIe (ADR-011, measured 2026-11-10). ``cuda`` requires the
    #: ``onnxruntime-gpu`` wheel and fails closed without it; ``auto`` prefers
    #: CUDA when the interpreter provides it. A CUDA session uses the fp32
    #: graphs when ``*_GPU_PATH`` is set, because those are the graphs with
    #: real CUDA kernels and the only ones that meet the 50 ms budget.
    classifier_execution_provider: Literal["cpu", "cuda", "auto"] = "cpu"

    # -- HITL approvals ----------------------------------------------------
    approval_hmac_secret: SecretStr = SecretStr(DEV_APPROVAL_HMAC_SECRET)
    approval_ttl_seconds: int = 900
    #: HMAC key for identity-bearing ARQ jobs (ADR-018). The gateway and the
    #: demo CLI mint with it; the worker only verifies. Distinct from
    #: ``APPROVAL_HMAC_SECRET`` so a leaked job key cannot mint capabilities.
    job_signing_secret: SecretStr = SecretStr(DEV_JOB_SIGNING_SECRET)
    #: How long an enqueued job envelope stays valid. Bounded because a queued
    #: payload is a bearer token until the worker burns its nonce.
    job_signature_ttl_seconds: int = 900

    # -- Guarded tools (four-eyes execution) ------------------------------
    #: ADR-009 Gate 1 allow-list. Relative to the working directory in local
    #: development and to ``/app`` in the container (``docs/`` is copied in).
    tool_catalog_path: str = "docs/tools/v1.json"
    #: Root the built-in file tools are confined to. It is created on demand
    #: with owner-only permissions; absolute and traversing paths are rejected.
    tool_workspace_root: str = "/tmp/bastion-workspace"  # noqa: S108 - sandboxed, owner-only
    tool_max_read_bytes: int = 262_144
    tool_max_write_bytes: int = 1_048_576
    #: Reject argument payloads larger than this before creating a ticket.
    tool_max_argument_bytes: int = 1_048_576
    #: Enqueue an approved ticket for immediate execution. The worker's
    #: approved-ticket sweep is the safety net when this is off or Redis is down.
    tool_resume_auto_enqueue: bool = True
    #: ARQ connection timeout for the gateway's enqueue bridge.
    arq_connection_timeout_seconds: float = 2.0
    #: Single queue name shared by the worker and the gateway's enqueue bridge.
    arq_queue_name: str = "bastion:jobs"

    # -- OmniRoute inference router ---------------------------------------
    omniroute_base_url: str = "http://localhost:8001"
    omniroute_api_key: SecretStr = SecretStr("sk-local-dev")
    omniroute_timeout_seconds: float = 120.0
    omniroute_max_retries: int = 1
    omniroute_retry_backoff_seconds: float = 0.25
    model_local_alias: str = "local-llama"
    model_cloud_alias: str = "cloud-primary"
    #: First target of each OmniRoute combo, router prefix removed; mirrors
    #: config/omniroute/config.yaml (tests/test_routing_client.py pins the pair).
    #: Telemetry reports these as the requested model, so a trace never claims a
    #: routing alias is a model id.
    model_local_primary: str = "qwen2.5-7b-instruct-q4_k_m"
    model_cloud_primary: str = "openai/gpt-4o-mini"

    # -- Observability -----------------------------------------------------
    otel_enabled: bool = True
    otel_service_name: str = "bastion-gateway"
    otel_exporter_otlp_endpoint: str = "http://localhost:4318"
    otel_traces_sampler_ratio: float = 1.0

    # -- Egress sanitizer --------------------------------------------------
    #: Marker prefix embedded in the system instructions and scanned for in
    #: model output. A hit quarantines the session. Must be at least
    #: :data:`CANARY_PREFIX_MIN_LENGTH` characters; a short marker matches
    #: ordinary text and would quarantine benign answers.
    canary_prefix: str = "BASTION-CANARY-"
    #: Quarantine window after a canary leak. Longer than one request and short
    #: enough that a false positive does not lock a conversation out for long.
    egress_trip_ttl_seconds: int = 900

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    @field_validator(
        "keycloak_jwks_uri",
        "keycloak_authorization_uri",
        "keycloak_token_uri",
        "keycloak_end_session_uri",
        "classifier_model_path",
        "classifier_tokenizer_path",
        "classifier_injection_model_path",
        "classifier_injection_tokenizer_path",
        "classifier_safety_model_path",
        "classifier_safety_tokenizer_path",
        "classifier_injection_model_sha256",
        "classifier_safety_model_sha256",
        "classifier_injection_model_gpu_path",
        "classifier_safety_model_gpu_path",
        "classifier_injection_model_gpu_sha256",
        "classifier_safety_model_gpu_sha256",
        "classifier_injection_threshold",
        "classifier_safety_unsafe_threshold_gpu",
        "payload_escrow_master_key",
        mode="before",
    )
    @classmethod
    def _blank_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("tenant_claim")
    @classmethod
    def _validate_tenant_claim(cls, value: str) -> str:
        claim = value.strip()
        if not claim or len(claim) > 128:
            raise ValueError("TENANT_CLAIM must be a non-empty claim name (max 128 characters)")
        return claim

    @field_validator("canary_prefix")
    @classmethod
    def _validate_canary_prefix(cls, value: str) -> str:
        if len(value) < CANARY_PREFIX_MIN_LENGTH:
            raise ValueError(
                f"CANARY_PREFIX must be at least {CANARY_PREFIX_MIN_LENGTH} characters; "
                f"got {len(value)}"
            )
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

    @field_validator("payload_escrow_master_key")
    @classmethod
    def _validate_payload_escrow_master_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        try:
            raw = base64.b64decode(value.get_secret_value(), validate=True)
        except (binascii.Error, ValueError) as exc:  # pragma: no cover - defensive
            raise ValueError("PAYLOAD_ESCROW_MASTER_KEY must be valid base64") from exc
        if len(raw) != 32:
            raise ValueError(
                "PAYLOAD_ESCROW_MASTER_KEY must decode to exactly 32 bytes (AES-256); "
                f"got {len(raw)}"
            )
        return value

    @field_validator(
        "otel_traces_sampler_ratio",
        "classifier_confidence_threshold",
        "classifier_injection_threshold",
        "classifier_safety_unsafe_threshold",
        "classifier_safety_unsafe_threshold_gpu",
        "classifier_safety_category_threshold",
        "dlp_score_threshold",
        "dlp_language_min_confidence",
    )
    @classmethod
    def _validate_ratio(cls, value: float | None) -> float | None:
        if value is not None and not 0.0 <= value <= 1.0:
            raise ValueError("value must be within [0.0, 1.0]")
        return value

    @field_validator(
        "session_ttl_seconds",
        "login_state_ttl_seconds",
        "logout_marker_ttl_seconds",
        "logout_target_ttl_seconds",
        "audit_page_size",
        "approval_page_size",
        "classifier_max_tokens",
        "classifier_injection_max_tokens",
        "classifier_safety_max_tokens",
        "tool_max_read_bytes",
        "tool_max_write_bytes",
        "tool_max_argument_bytes",
        "keycloak_jwks_cache_ttl_seconds",
        "egress_trip_ttl_seconds",
        "rate_limit_window_seconds",
        "rate_limit_dashboard_per_window",
        "rate_limit_chat_per_window",
        "payload_escrow_ttl_seconds",
        "response_store_max_chars",
        "audit_witness_retention_years",
    )
    @classmethod
    def _validate_positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("value must be a positive integer")
        return value

    @field_validator("omniroute_max_retries")
    @classmethod
    def _validate_retries(cls, value: int) -> int:
        if value < 0:
            raise ValueError("OMNIROUTE_MAX_RETRIES must be zero or positive")
        return value

    @field_validator("omniroute_retry_backoff_seconds")
    @classmethod
    def _validate_backoff(cls, value: float) -> float:
        if value < 0:
            raise ValueError("OMNIROUTE_RETRY_BACKOFF_SECONDS must be zero or positive")
        return value

    @field_validator("dlp_entities")
    @classmethod
    def _normalise_entities(cls, value: str) -> str:
        parts = tuple(
            dict.fromkeys(part.strip().upper() for part in value.split(",") if part.strip())
        )
        if not parts:
            raise ValueError("DLP_ENTITIES must contain at least one entity type")
        return ",".join(parts)

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        level = value.upper()
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        if level not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(allowed)}")
        return level

    @field_validator(
        "classifier_injection_model_sha256",
        "classifier_safety_model_sha256",
        "classifier_injection_model_gpu_sha256",
        "classifier_safety_model_gpu_sha256",
    )
    @classmethod
    def _validate_sha256(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalised = value.strip().lower()
        if len(normalised) != 64 or any(char not in "0123456789abcdef" for char in normalised):
            raise ValueError("model digest must be 64 hexadecimal characters")
        return normalised

    @model_validator(mode="after")
    def _reject_dev_secrets(self) -> Settings:
        # Checked first so the message is about the offending flag, not about
        # secrets, when an operator tries to enable debugging escrow in prod.
        if self.environment == "production" and self.payload_escrow_enabled:
            raise ValueError(
                "PAYLOAD_ESCROW_ENABLED must be false in production: payload escrow is a "
                "pre-production debugging store that recovers plaintext PII (ADR-005 decision 7)"
            )
        if self.environment not in {"staging", "production"}:
            return self
        if self.vault_master_key.get_secret_value() == DEV_VAULT_MASTER_KEY:
            raise ValueError("VAULT_MASTER_KEY must be rotated before non-local deployment")
        if self.approval_hmac_secret.get_secret_value() == DEV_APPROVAL_HMAC_SECRET:
            raise ValueError("APPROVAL_HMAC_SECRET must be rotated before non-local deployment")
        if self.job_signing_secret.get_secret_value() == DEV_JOB_SIGNING_SECRET:
            raise ValueError("JOB_SIGNING_SECRET must be rotated before non-local deployment")
        if self.audit_witness_hmac_secret.get_secret_value() == DEV_AUDIT_WITNESS_HMAC_SECRET:
            raise ValueError(
                "AUDIT_WITNESS_HMAC_SECRET must be rotated before non-local deployment"
            )
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
    def dlp_entity_list(self) -> tuple[str, ...]:
        """Presidio entity types as an immutable tuple."""
        return tuple(self.dlp_entities.split(","))

    @property
    def classifier_ensemble_enabled(self) -> bool:
        """Both ensemble graphs are configured."""
        return (
            self.classifier_injection_model_path is not None
            and self.classifier_safety_model_path is not None
        )

    @property
    def injection_threshold(self) -> float:
        """Injection threshold: explicit override, else the profile default."""
        if self.classifier_injection_threshold is not None:
            return self.classifier_injection_threshold
        return 0.5 if self.classifier_injection_profile == "recall-first" else 0.662

    @property
    def vault_key_bytes(self) -> bytes:
        """The 32-byte AES-256 key backing the reversible token vault."""
        return base64.b64decode(self.vault_master_key.get_secret_value())

    @property
    def payload_escrow_key_bytes(self) -> bytes:
        """The 32-byte AES-256 key backing the pre-production payload escrow.

        A dedicated ``PAYLOAD_ESCROW_MASTER_KEY`` wins when set. Otherwise the
        key is HKDF-SHA256 of the vault master key under a fixed label, so the
        escrow and the token vault never share key material and an operator does
        not have to provision a second secret. Rotating the vault key therefore
        invalidates outstanding escrow rows; the 24-hour default window keeps
        that cost bounded.
        """
        if self.payload_escrow_master_key is not None:
            return base64.b64decode(self.payload_escrow_master_key.get_secret_value())
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"bastion-payload-escrow-v1",
        ).derive(self.vault_key_bytes)

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
