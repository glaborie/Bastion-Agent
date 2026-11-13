"""SQLAlchemy 2.0 persistence models for Bastion-Agent.

Three append-only-in-spirit tables back the control plane:

``audit_logs``
    A tamper-evident, SHA-256 hash-chained ledger. Every record commits the hash
    of the previous record, so mutating or deleting any entry breaks verification
    for all subsequent entries.

``pending_approvals``
    Suspended mutating tool calls awaiting four-eyes human approval. The database
    itself rejects self-approval via a ``CHECK`` constraint, so the separation-of-
    duties rule holds even if an application-level check is bypassed.

``payload_escrow``
    A pre-production-only, short-lived AES-256-GCM copy of a payload the ledger
    hashed. It is deliberately a *separate* table: ``audit_logs`` stays hash-only
    and append-only, the chain is never rewritten, and expiry is a row delete
    here rather than an update there (ADR-005 decision 7).

The pure functions in this module (hashing, canonicalisation, token signing) are
deliberately side-effect free so they can be property-tested and reused by both
the gateway and the ARQ worker.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final

from sqlalchemy import (
    DDL,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    MetaData,
    Sequence,
    String,
    event,
    text,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Hash assigned to the ``previous_hash`` column of the very first audit record.
GENESIS_HASH: Final[str] = "0" * 64

#: Hex digest length for SHA-256 / HMAC-SHA256 material.
_HASH_HEX_LENGTH: Final[int] = 64

#: PostgreSQL advisory-lock key serialising audit-chain appends. Any constant
#: works; it only has to be stable and distinct from other locks in the system.
AUDIT_CHAIN_LOCK_ID: Final[int] = 7_126_552_001

#: Advisory-lock key guarding concurrent schema initialisation across replicas.
SCHEMA_INIT_LOCK_ID: Final[int] = 7_126_552_002

_NAMING_CONVENTION: Final[dict[str, str]] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base carrying a deterministic constraint naming convention."""

    metadata = MetaData(naming_convention=_NAMING_CONVENTION)


#: Sequence supplying audit-log identifiers. IDs are allocated inside the
#: append transaction (under the chain lock) because the record hash must
#: include the identifier before the row is written.
AUDIT_LOG_ID_SEQUENCE: Final = Sequence("audit_logs_id_seq", metadata=Base.metadata)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AuditEventType(StrEnum):
    """Canonical audit event vocabulary (see HANDOVER_SPEC §3.5)."""

    INPUT_RECEIVED = "INPUT_RECEIVED"
    DLP_REDACTION = "DLP_REDACTION"
    ROUTING_DECISION = "ROUTING_DECISION"
    TOOL_REQUESTED = "TOOL_REQUESTED"
    TOOL_EXECUTED = "TOOL_EXECUTED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    EGRESS_FILTERED = "EGRESS_FILTERED"
    SECURITY_INCIDENT = "SECURITY_INCIDENT"
    #: An ``admin`` read one payload-escrow row (ADR-005 decision 7). The
    #: metadata carries the audit id, kind and outcome — never the plaintext.
    ESCROW_ACCESSED = "ESCROW_ACCESSED"
    #: The sanitized answer handed to the caller (ADR-005 decision 8). The
    #: payload is the delivered text, or its configured prefix when truncated.
    RESPONSE_SENT = "RESPONSE_SENT"


class EscrowKind(StrEnum):
    """What a ``payload_escrow`` row holds.

    ``input_raw`` is the raw pre-DLP request (IDEA-016). ``egress_delivered`` is
    the sanitized answer after egress, which is what the user actually saw
    (IDEA-029). Both use the same key, AAD shape and retention; the kind is part
    of the associated data so a ciphertext cannot be relabelled.
    """

    INPUT_RAW = "input_raw"
    EGRESS_DELIVERED = "egress_delivered"


class ApprovalStatus(StrEnum):
    """Lifecycle of a suspended tool call."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"


def _enum_values(enum_cls: type[StrEnum]) -> list[str]:
    """Persist the *values* (not member names) of a ``StrEnum``."""
    return [str(member.value) for member in enum_cls]


def _enum_column(name: str, enum_cls: type[Any]) -> SAEnum:
    """A portable VARCHAR-backed enum with an accompanying CHECK constraint."""
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        values_callable=_enum_values,
        length=32,
    )


# ---------------------------------------------------------------------------
# Canonicalisation & hashing primitives
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    """Timezone-aware UTC clock (monkeypatchable in tests)."""
    return datetime.now(UTC)


def canonical_timestamp(value: datetime) -> str:
    """Render a timestamp so Python and PostgreSQL agree on the exact string."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def canonical_payload_bytes(payload: Any) -> bytes:
    """Serialise a payload in the canonical form every hash and escrow uses.

    ``bytes``/``str`` are taken verbatim; everything else becomes deterministic
    JSON (sorted keys, no whitespace). The escrow stores exactly these bytes, so
    hashing the decrypted payload reproduces ``payload_hash`` bit for bit.
    """
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def hash_payload(payload: Any) -> str:
    """SHA-256 a payload in a canonical, order-independent form.

    ``bytes``/``str`` are hashed verbatim; everything else is serialised as
    deterministic JSON (sorted keys, no whitespace) so that semantically equal
    payloads always produce the same digest.
    """
    return hashlib.sha256(canonical_payload_bytes(payload)).hexdigest()


def compute_record_hash(
    *,
    record_id: int,
    timestamp: datetime,
    actor_id: str,
    event_type: str,
    payload_hash: str,
    previous_hash: str,
) -> str:
    """Compute ``record_hash`` exactly as specified in HANDOVER_SPEC §3.5.

    ``SHA256(id + timestamp + actor_id + event_type + payload_hash + previous_hash)``
    with fields joined by ``|`` after canonicalisation.
    """
    for label, digest in (("payload_hash", payload_hash), ("previous_hash", previous_hash)):
        if len(digest) != _HASH_HEX_LENGTH:
            raise ValueError(f"{label} must be a {_HASH_HEX_LENGTH}-character hex digest")
    material = "|".join(
        (
            str(record_id),
            canonical_timestamp(timestamp),
            actor_id,
            str(event_type),
            payload_hash,
            previous_hash,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Audit ledger
# ---------------------------------------------------------------------------


class AuditLog(Base):
    """An immutable, hash-chained audit record.

    ``metadata_json`` must never contain raw PII or secrets: audit entries are
    retained long after the DLP token vault has expired.

    Append-only is enforced by a PostgreSQL trigger (see the DDL listeners below),
    not merely by convention. UPDATE/DELETE raise ``insufficient_privilege``
    unless the transaction explicitly sets ``bastion.allow_audit_mutation = on``
    (used only by integrity tests and break-glass maintenance).
    """

    __tablename__ = "audit_logs"

    # ID is allocated from AUDIT_LOG_ID_SEQUENCE inside the append transaction,
    # because the hash covers the identifier. Never let the database invent it
    # asynchronously.
    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=False,
        server_default=AUDIT_LOG_ID_SEQUENCE.next_value(),
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
    )
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: Access scope from the authenticated identity (ADR-015). Not part of the
    #: record hash, which ADR-005 keeps stable; the append-only trigger prevents
    #: reassigning it.
    tenant_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True, server_default=text("'default'")
    )
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[AuditEventType] = mapped_column(
        _enum_column("audit_event_type", AuditEventType), nullable=False
    )
    payload_hash: Mapped[str] = mapped_column(String(_HASH_HEX_LENGTH), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    previous_hash: Mapped[str] = mapped_column(String(_HASH_HEX_LENGTH), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(_HASH_HEX_LENGTH), nullable=False, unique=True)

    __table_args__ = (
        CheckConstraint("record_hash ~ '^[0-9a-f]{64}$'", name="record_hash_is_sha256_hex"),
        CheckConstraint("previous_hash ~ '^[0-9a-f]{64}$'", name="previous_hash_is_sha256_hex"),
        CheckConstraint("payload_hash ~ '^[0-9a-f]{64}$'", name="payload_hash_is_sha256_hex"),
        Index("ix_audit_logs_timestamp_id", "timestamp", "id"),
        Index("ix_audit_logs_tenant_timestamp_id", "tenant_id", "timestamp", "id"),
        Index("ix_audit_logs_session_id", "session_id"),
        Index("ix_audit_logs_actor_id", "actor_id"),
        Index("ix_audit_logs_event_type", "event_type"),
    )

    def compute_hash(self) -> str:
        """Recompute this record's hash from its current field values."""
        if self.id is None:  # pragma: no cover - guarded by the append path
            raise ValueError("audit record id must be assigned before hashing")
        return compute_record_hash(
            record_id=int(self.id),
            timestamp=self.timestamp,
            actor_id=self.actor_id,
            event_type=str(self.event_type),
            payload_hash=self.payload_hash,
            previous_hash=self.previous_hash,
        )

    def verify(self) -> bool:
        """Constant-time check that the stored hash matches the record contents."""
        return hmac.compare_digest(self.record_hash, self.compute_hash())

    def __repr__(self) -> str:
        return (
            f"AuditLog(id={self.id!r}, event_type={self.event_type!r}, actor_id={self.actor_id!r})"
        )


# ---------------------------------------------------------------------------
# Audit immutability guard (ADR-001 / ADR-005)
# ---------------------------------------------------------------------------

#: The ledger is append-only by construction. A row-level trigger rejects UPDATE
#: and DELETE. Integrity tests (and documented break-glass maintenance) can opt
#: out for the duration of one transaction with:
#:     SELECT set_config('bastion.allow_audit_mutation', 'on', true);
#: TRUNCATE is intentionally still allowed: it is a DDL reset (used by tests and
#: disaster recovery), and it leaves the chain visibly empty rather than forked.
_AUDIT_APPEND_ONLY_FUNCTION: Final[str] = """
CREATE OR REPLACE FUNCTION bastion_audit_logs_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('bastion.allow_audit_mutation', true) = 'on' THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    -- No format placeholders here: SQLAlchemy formats DDL strings.
    RAISE EXCEPTION 'audit_logs is append-only'
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'blocked operation: ' || TG_OP;
END;
$$;
"""

_AUDIT_APPEND_ONLY_TRIGGER: Final[str] = """
CREATE TRIGGER trg_audit_logs_append_only
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION bastion_audit_logs_append_only();
"""

_AUDIT_APPEND_ONLY_DROP_FUNCTION: Final[str] = (
    "DROP FUNCTION IF EXISTS bastion_audit_logs_append_only() CASCADE"
)

#: Idempotent statements applied on every boot by ``db.session.init_models`` so
#: existing databases (where ``after_create`` never fires) also get the guard.
AUDIT_APPEND_ONLY_DDL: Final[tuple[str, ...]] = (
    _AUDIT_APPEND_ONLY_FUNCTION,
    "DROP TRIGGER IF EXISTS trg_audit_logs_append_only ON audit_logs",
    _AUDIT_APPEND_ONLY_TRIGGER,
)

event.listen(
    AuditLog.__table__,
    "after_create",
    DDL(_AUDIT_APPEND_ONLY_FUNCTION).execute_if(  # type: ignore[no-untyped-call]
        dialect="postgresql"
    ),
)
event.listen(
    AuditLog.__table__,
    "after_create",
    DDL(_AUDIT_APPEND_ONLY_TRIGGER).execute_if(  # type: ignore[no-untyped-call]
        dialect="postgresql"
    ),
)
event.listen(
    AuditLog.__table__,
    "before_drop",
    DDL(_AUDIT_APPEND_ONLY_DROP_FUNCTION).execute_if(  # type: ignore[no-untyped-call]
        dialect="postgresql"
    ),
)


#: The event vocabulary is a VARCHAR CHECK constraint, not a native enum, so a
#: new ``AuditEventType`` member needs the constraint widened on databases that
#: already exist (``create_all`` never alters one). The block is idempotent: it
#: rewrites the constraint only when the newest member is missing, so a fresh
#: database and every later boot do no work. New members must be appended to
#: ``AuditEventType`` and added to the list below; ``tests/test_settings.py``
#: fails if the two drift apart.
AUDIT_EVENT_VOCABULARY_DDL: Final[tuple[str, ...]] = (
    """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_audit_logs_audit_event_type'
          AND pg_get_constraintdef(oid) LIKE '%RESPONSE_SENT%'
    ) THEN
        ALTER TABLE audit_logs
            DROP CONSTRAINT IF EXISTS ck_audit_logs_audit_event_type;
        ALTER TABLE audit_logs
            ADD CONSTRAINT ck_audit_logs_audit_event_type
            CHECK (event_type IN (
                'INPUT_RECEIVED',
                'DLP_REDACTION',
                'ROUTING_DECISION',
                'TOOL_REQUESTED',
                'TOOL_EXECUTED',
                'APPROVAL_REQUESTED',
                'APPROVAL_GRANTED',
                'APPROVAL_REJECTED',
                'EGRESS_FILTERED',
                'SECURITY_INCIDENT',
                'ESCROW_ACCESSED',
                'RESPONSE_SENT'
            ));
    END IF;
END
$$;
""",
)

#: The escrow kind is a VARCHAR CHECK constraint for the same reason. A database
#: created before ``egress_delivered`` existed already has the table, and
#: ``create_all`` never widens its constraint.
ESCROW_KIND_DDL: Final[tuple[str, ...]] = (
    """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_payload_escrow_escrow_kind'
          AND pg_get_constraintdef(oid) LIKE '%egress_delivered%'
    ) THEN
        ALTER TABLE payload_escrow
            DROP CONSTRAINT IF EXISTS ck_payload_escrow_escrow_kind;
        ALTER TABLE payload_escrow
            ADD CONSTRAINT ck_payload_escrow_escrow_kind
            CHECK (kind IN ('input_raw', 'egress_delivered'));
    END IF;
END
$$;
""",
)


# ---------------------------------------------------------------------------
# Four-eyes pending approvals
# ---------------------------------------------------------------------------


def fingerprint_request(tool_name: str, arguments: Mapping[str, Any]) -> str:
    """Bind an approval to the *exact* tool invocation (prevents TOCTOU swaps)."""
    return hash_payload({"tool": tool_name, "arguments": dict(arguments)})


_APPROVAL_TOKEN_VERSION: Final[str] = "v1"  # noqa: S105 - format tag, not a secret


def _approval_token_message(
    *, ticket_id: uuid.UUID | str, request_fingerprint: str, expires_at: datetime
) -> bytes:
    return "|".join(
        (
            _APPROVAL_TOKEN_VERSION,
            str(ticket_id),
            request_fingerprint,
            canonical_timestamp(expires_at),
        )
    ).encode("utf-8")


def sign_approval_token(
    *,
    ticket_id: uuid.UUID | str,
    request_fingerprint: str,
    expires_at: datetime,
    secret: str,
) -> str:
    """Produce an HMAC-SHA256 capability token for one specific approval ticket."""
    if not secret:
        raise ValueError("approval HMAC secret must not be empty")
    digest = hmac.new(
        secret.encode("utf-8"),
        _approval_token_message(
            ticket_id=ticket_id,
            request_fingerprint=request_fingerprint,
            expires_at=expires_at,
        ),
        hashlib.sha256,
    ).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{_APPROVAL_TOKEN_VERSION}.{encoded}"


def hash_approval_token(token: str) -> str:
    """Hash a token for at-rest storage; the plaintext token is never persisted."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_approval_token(
    *,
    token: str,
    ticket_id: uuid.UUID | str,
    request_fingerprint: str,
    expires_at: datetime,
    secret: str,
) -> bool:
    """Constant-time verification of a presented approval token."""
    expected = sign_approval_token(
        ticket_id=ticket_id,
        request_fingerprint=request_fingerprint,
        expires_at=expires_at,
        secret=secret,
    )
    return hmac.compare_digest(token, expected)


class PendingApproval(Base):
    """A mutating tool call suspended under the four-eyes principle."""

    __tablename__ = "pending_approvals"

    ticket_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    #: Tenant of the initiator; the approver must be in the same tenant.
    tenant_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True, server_default=text("'default'")
    )
    initiator_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_arguments: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    required_role: Mapped[str] = mapped_column(String(32), nullable=False)

    #: SHA-256 of the canonical (tool, arguments) pair.
    request_fingerprint: Mapped[str] = mapped_column(String(_HASH_HEX_LENGTH), nullable=False)
    #: SHA-256 of the issued HMAC token — the token itself is never stored.
    approval_token_hash: Mapped[str] = mapped_column(String(_HASH_HEX_LENGTH), nullable=False)
    token_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    status: Mapped[ApprovalStatus] = mapped_column(
        _enum_column("approval_status", ApprovalStatus),
        nullable=False,
        default=ApprovalStatus.PENDING,
        server_default=ApprovalStatus.PENDING.value,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=text("now()"),
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approver_id: Mapped[str | None] = mapped_column(String(128))
    decision_reason: Mapped[str | None] = mapped_column(String(1024))
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        # Enforce separation of duties at the storage layer. The application also
        # checks this, but defence in depth means a bypassed code path still fails.
        CheckConstraint(
            "approver_id IS NULL OR approver_id <> initiator_id",
            name="four_eyes_separation",
        ),
        CheckConstraint(
            "approver_id IS NULL OR length(trim(approver_id)) > 0",
            name="approver_id_not_blank",
        ),
        CheckConstraint(
            "status NOT IN ('approved', 'executed', 'failed') "
            "OR (approver_id IS NOT NULL AND decided_at IS NOT NULL)",
            name="terminal_decision_recorded",
        ),
        CheckConstraint(
            "request_fingerprint ~ '^[0-9a-f]{64}$'",
            name="request_fingerprint_is_sha256_hex",
        ),
        CheckConstraint(
            "approval_token_hash ~ '^[0-9a-f]{64}$'",
            name="approval_token_hash_is_sha256_hex",
        ),
        Index("ix_pending_approvals_status_expires", "status", "token_expires_at"),
        Index(
            "ix_pending_approvals_tenant_status_expires",
            "tenant_id",
            "status",
            "token_expires_at",
        ),
        Index("ix_pending_approvals_initiator_id", "initiator_id"),
        Index("ix_pending_approvals_session_id", "session_id"),
    )

    # -- Derived state -----------------------------------------------------
    def __init__(self, **kwargs: Any) -> None:
        # Insert-time defaults are not applied to transient instances, so seed
        # the invariants we rely on before the object is persisted.
        kwargs.setdefault("status", ApprovalStatus.PENDING)
        kwargs.setdefault("tool_arguments", {})
        super().__init__(**kwargs)

    @property
    def is_expired(self) -> bool:
        """True once the approval window has closed (regardless of status)."""
        return utcnow() >= self.token_expires_at

    @property
    def is_decidable(self) -> bool:
        """True when the ticket is still open and within its validity window."""
        return self.status == ApprovalStatus.PENDING and not self.is_expired

    def can_be_decided_by(self, actor_id: str) -> bool:
        """Four-eyes guard: a pending ticket cannot be decided by its initiator."""
        return self.is_decidable and actor_id != self.initiator_id

    @staticmethod
    def expiry_for(issued_at: datetime, ttl_seconds: int) -> datetime:
        """Expiry for a ticket issued at ``issued_at`` with the configured TTL."""
        if ttl_seconds <= 0:
            raise ValueError("approval TTL must be positive")
        return issued_at + timedelta(seconds=ttl_seconds)

    def __repr__(self) -> str:
        return (
            f"PendingApproval(ticket_id={self.ticket_id!r}, tool={self.tool_name!r}, "
            f"status={self.status!r})"
        )


# ---------------------------------------------------------------------------
# Payload escrow (ADR-005 decision 7)
# ---------------------------------------------------------------------------


class PayloadEscrow(Base):
    """A short-lived, encrypted copy of one hashed audit payload.

    Pre-production debugging only. The row is keyed to the audit record it
    explains, but it lives outside ``audit_logs``: the ledger stays hash-only and
    append-only, so writing or purging escrow rows cannot change a chain link.
    ``payload_hash`` is copied from the ledger row, and the writer refuses to
    store a payload whose digest differs, so a decrypt can always be checked
    against the ledger.

    Access is deliberately not append-only: expiry deletes the row (and its
    plaintext capability) outright. The surviving evidence is the ledger row.
    """

    __tablename__ = "payload_escrow"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    #: The ledger record this ciphertext explains. RESTRICT because the ledger
    #: trigger already forbids deleting the parent; the FK only prevents an
    #: orphan escrow row from being written.
    audit_log_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("audit_logs.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    #: Access scope of the escrowed event (ADR-015); a read must match it.
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    kind: Mapped[EscrowKind] = mapped_column(
        _enum_column("escrow_kind", EscrowKind), nullable=False
    )
    #: Copied from ``audit_logs.payload_hash`` so a decrypt is verifiable alone.
    payload_hash: Mapped[str] = mapped_column(String(_HASH_HEX_LENGTH), nullable=False)
    #: Per-record AES-GCM nonce and the ciphertext it authenticates.
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=text("now()"),
    )
    #: Set by the writer from ``PAYLOAD_ESCROW_TTL_SECONDS``; the purge deletes
    #: rows at or past it. The column is indexed because the purge is a range
    #: delete on every worker sweep.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("payload_hash ~ '^[0-9a-f]{64}$'", name="payload_hash_is_sha256_hex"),
        CheckConstraint("octet_length(nonce) = 12", name="nonce_is_12_bytes"),
        CheckConstraint("expires_at > created_at", name="expires_after_creation"),
        Index("ix_payload_escrow_expires_at", "expires_at"),
        Index("ix_payload_escrow_tenant_created_at", "tenant_id", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"PayloadEscrow(id={self.id!r}, audit_log_id={self.audit_log_id!r}, kind={self.kind!r})"
        )


# ---------------------------------------------------------------------------
# Tenant-scope upgrade path (ADR-015)
# ---------------------------------------------------------------------------

#: ``create_all`` only creates missing tables, so an existing v0.2 database
#: needs the tenant columns added in place. ``ADD COLUMN ... DEFAULT`` is a
#: metadata-only change on PostgreSQL 11+; the indexes are created idempotently
#: on boot (a large production ledger should use an explicit online migration).
#: Rows that predate ADR-015 are assigned ``default``; new application writes
#: always pass a validated tenant explicitly.
TENANT_SCOPE_DDL: Final[tuple[str, ...]] = (
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS "
    "tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'",
    "ALTER TABLE pending_approvals ADD COLUMN IF NOT EXISTS "
    "tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'",
    "CREATE INDEX IF NOT EXISTS ix_audit_logs_tenant_id ON audit_logs (tenant_id)",
    "CREATE INDEX IF NOT EXISTS ix_audit_logs_tenant_timestamp_id "
    "ON audit_logs (tenant_id, timestamp, id)",
    "CREATE INDEX IF NOT EXISTS ix_pending_approvals_tenant_id ON pending_approvals (tenant_id)",
    "CREATE INDEX IF NOT EXISTS ix_pending_approvals_tenant_status_expires "
    "ON pending_approvals (tenant_id, status, token_expires_at)",
)
