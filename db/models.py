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

The ORM tables and their DDL live here. The pure primitives they depend on —
canonical serialisation, SHA-256 chain hashing and approval-token signing — live
in :mod:`db.hashing` and :mod:`db.tokens` and are re-exported below, so
``from db.models import compute_record_hash`` keeps working.
"""

from __future__ import annotations

import hmac
import uuid
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
    SmallInteger,
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

# Re-exported for callers that import the primitive from here (ADR-005 decision
# 2); the definitions live in db.hashing and db.tokens. The redundant aliases
# are what mark the re-export as explicit for mypy.
# pylint: disable=useless-import-alias,unused-import
from db.hashing import CURRENT_HASH_VERSION as CURRENT_HASH_VERSION
from db.hashing import HASH_HEX_LENGTH as _HASH_HEX_LENGTH
from db.hashing import canonical_payload_bytes as canonical_payload_bytes
from db.hashing import canonical_timestamp as canonical_timestamp
from db.hashing import compute_record_hash as compute_record_hash
from db.hashing import hash_payload as hash_payload
from db.tokens import fingerprint_request as fingerprint_request
from db.tokens import hash_approval_token as hash_approval_token
from db.tokens import sign_approval_token as sign_approval_token
from db.tokens import verify_approval_token as verify_approval_token

# pylint: enable=useless-import-alias,unused-import

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Hash assigned to the ``previous_hash`` column of the very first audit record.
GENESIS_HASH: Final[str] = "0" * 64

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
    #: A ticket whose approval window lapsed without a decision (ADR-010
    #: decision 8).
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    #: The caller's recent history reads as frustrated and an operator handoff
    #: is waiting (ADR-022). Metadata carries the verdict and the marker count,
    #: never the conversation text. Appended last so the DDL guard below widens
    #: existing rows.
    HANDOFF_REQUIRED = "HANDOFF_REQUIRED"
    #: An operator took ownership of a queued handoff (ADR-022 decision 9).
    #: Metadata carries the conversation id and verdict; the actor and timestamp
    #: are the row's own. One row per conversation, so a repeat call is a no-op.
    HANDOFF_ACKNOWLEDGED = "HANDOFF_ACKNOWLEDGED"


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
# Clock
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    """Timezone-aware UTC clock (monkeypatchable in tests)."""
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Audit ledger
# ---------------------------------------------------------------------------


class AuditLog(Base):
    """An immutable, hash-chained audit record.

    ``metadata_json`` must never contain raw PII or secrets: audit entries are
    retained long after the DLP token vault has expired.

    Append-only is enforced by a PostgreSQL trigger (see the DDL listeners below),
    not merely by convention. UPDATE and DELETE always raise
    ``insufficient_privilege``; break-glass maintenance is owner DDL that
    disables the trigger, and the runtime role can neither do that nor truncate
    the table (IDEA-062).
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
    #: Whether ``actor_id`` names a human subject or a registered agent
    #: (ADR-027). v3 rows hash this triple; v1/v2 rows keep ``human``/NULL and
    #: their original preimage.
    actor_type: Mapped[str] = mapped_column(
        String(16), nullable=False, default="human", server_default=text("'human'")
    )
    #: The Keycloak client id of a non-human caller, NULL for humans.
    agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: The human subject an agent acts for; NULL for humans.
    owner_sub: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_type: Mapped[AuditEventType] = mapped_column(
        _enum_column("audit_event_type", AuditEventType), nullable=False
    )
    payload_hash: Mapped[str] = mapped_column(String(_HASH_HEX_LENGTH), nullable=False)
    #: Preimage version: 1 predates the metadata digest, 2 covers it.
    hash_version: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=CURRENT_HASH_VERSION, server_default=text("3")
    )
    #: SHA-256 of ``canonical_payload_bytes(metadata_json)`` for v2 rows; NULL
    #: on v1 rows, whose original preimage must keep verifying.
    metadata_hash: Mapped[str | None] = mapped_column(String(_HASH_HEX_LENGTH), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    previous_hash: Mapped[str] = mapped_column(String(_HASH_HEX_LENGTH), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(_HASH_HEX_LENGTH), nullable=False, unique=True)

    __table_args__ = (
        CheckConstraint("record_hash ~ '^[0-9a-f]{64}$'", name="record_hash_is_sha256_hex"),
        CheckConstraint("previous_hash ~ '^[0-9a-f]{64}$'", name="previous_hash_is_sha256_hex"),
        CheckConstraint("payload_hash ~ '^[0-9a-f]{64}$'", name="payload_hash_is_sha256_hex"),
        CheckConstraint(
            "(hash_version = 1 AND metadata_hash IS NULL) "
            "OR (hash_version IN (2, 3) AND metadata_hash ~ '^[0-9a-f]{64}$')",
            name="hash_version_metadata",
        ),
        CheckConstraint(
            "(hash_version < 3 AND actor_type = 'human' "
            "AND agent_id IS NULL AND owner_sub IS NULL) "
            "OR (hash_version = 3 AND actor_type IN ('human', 'agent') "
            "AND ((actor_type = 'human' AND agent_id IS NULL AND owner_sub IS NULL) "
            "OR (actor_type = 'agent' AND agent_id IS NOT NULL)))",
            name="actor_type_fields",
        ),
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
            hash_version=self.hash_version,
            metadata_hash=self.metadata_hash,
            actor_type=self.actor_type,
            agent_id=self.agent_id,
            owner_sub=self.owner_sub,
        )

    def verify(self) -> bool:
        """Constant-time check that the stored hash matches the record contents.

        A v2 row also has to prove its ``metadata_hash`` still describes the
        current ``metadata_json``: the record hash covers the digest column, so
        checking only the hash would let an edit of the JSON metadata pass.
        """
        if self.hash_version >= 2 and (
            self.metadata_hash is None
            or not hmac.compare_digest(self.metadata_hash, hash_payload(self.metadata_json))
        ):
            return False
        return hmac.compare_digest(self.record_hash, self.compute_hash())

    def __repr__(self) -> str:
        return (
            f"AuditLog(id={self.id!r}, event_type={self.event_type!r}, actor_id={self.actor_id!r})"
        )


# ---------------------------------------------------------------------------
# Audit immutability guard (ADR-001 / ADR-005)
# ---------------------------------------------------------------------------

#: The ledger is append-only by construction. A row-level trigger always rejects
#: UPDATE and DELETE; break-glass maintenance is owner DDL (disable the trigger,
#: mutate, re-enable) and the runtime role cannot run it. TRUNCATE is refused by
#: table privilege for the runtime role and remains an explicit owner reset.
_AUDIT_APPEND_ONLY_FUNCTION: Final[str] = """
CREATE OR REPLACE FUNCTION bastion_audit_logs_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
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
          AND pg_get_constraintdef(oid) LIKE '%HANDOFF_ACKNOWLEDGED%'
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
                'RESPONSE_SENT',
                'APPROVAL_EXPIRED',
                'HANDOFF_REQUIRED',
                'HANDOFF_ACKNOWLEDGED'
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


#: The versioned hash columns are also added idempotently: ``create_all`` never
#: alters an existing table, and a database that predates this change must keep
#: its rows verifiable as v1 while new rows are written as v2. The CHECK name
#: matches the model's naming convention so a fresh database needs no rewrite.
AUDIT_HASH_VERSION_DDL: Final[tuple[str, ...]] = (
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS hash_version SMALLINT NOT NULL DEFAULT 1",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS metadata_hash CHAR(64)",
    """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_audit_logs_hash_version_metadata'
    ) THEN
        ALTER TABLE audit_logs
            ADD CONSTRAINT ck_audit_logs_hash_version_metadata
            CHECK (
                (hash_version = 1 AND metadata_hash IS NULL)
                OR (hash_version = 2 AND metadata_hash ~ '^[0-9a-f]{64}$')
            );
    END IF;
END
$$;
""",
)


#: v3 actor columns and the widened constraint, applied idempotently on boot.
#: Existing rows stay ``human``/NULL; only new appends are v3 (ADR-027).
AUDIT_ACTOR_DDL: Final[tuple[str, ...]] = (
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS "
    "actor_type VARCHAR(16) NOT NULL DEFAULT 'human'",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS agent_id VARCHAR(128)",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS owner_sub VARCHAR(128)",
    """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_audit_logs_hash_version_metadata'
          AND pg_get_constraintdef(oid) LIKE '%hash_version = 3%'
    ) THEN
        ALTER TABLE audit_logs
            DROP CONSTRAINT IF EXISTS ck_audit_logs_hash_version_metadata;
        ALTER TABLE audit_logs
            ADD CONSTRAINT ck_audit_logs_hash_version_metadata
            CHECK (
                (hash_version = 1 AND metadata_hash IS NULL)
                OR (hash_version IN (2, 3) AND metadata_hash ~ '^[0-9a-f]{64}$')
            );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_audit_logs_actor_type_fields'
    ) THEN
        ALTER TABLE audit_logs
            ADD CONSTRAINT ck_audit_logs_actor_type_fields
            CHECK (
                (hash_version < 3 AND actor_type = 'human'
                    AND agent_id IS NULL AND owner_sub IS NULL)
                OR (hash_version = 3 AND actor_type IN ('human', 'agent')
                    AND ((actor_type = 'human'
                            AND agent_id IS NULL AND owner_sub IS NULL)
                        OR (actor_type = 'agent' AND agent_id IS NOT NULL)))
            );
    END IF;
END
$$;
""",
)


# ---------------------------------------------------------------------------
# Non-human principals (ADR-027)
# ---------------------------------------------------------------------------


class AgentStatus(StrEnum):
    """Lifecycle of a registered agent principal."""

    ACTIVE = "active"
    SUSPENDED = "suspended"


class AgentRegistry(Base):
    """One non-human principal: a Keycloak client that acts for a human owner.

    The row is the registry entry the ingress consults after a
    ``client_credentials`` token validates. ``status`` is the single deny switch
    (there is no second quarantine table): ``suspended`` refuses the next call
    before any work is enqueued. ``allowed_tools`` narrows the global catalog;
    an empty list means "no tools", never "all tools".
    """

    __tablename__ = "agent_registry"

    #: The Keycloak client id (the token's ``azp``), not the service-account sub.
    agent_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    #: The human subject this agent acts for; carried into every ledger row.
    owner_sub: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True, server_default=text("'default'")
    )
    status: Mapped[AgentStatus] = mapped_column(
        _enum_column("agent_status", AgentStatus),
        nullable=False,
        default=AgentStatus.ACTIVE,
        server_default=AgentStatus.ACTIVE.value,
    )
    #: Hard stop independent of ``status``; NULL means no expiry configured.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Catalog tool names this agent may call. Never widens the catalog.
    allowed_tools: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    #: Model route aliases this agent may reach (ADR-027 decision 5).
    allowed_route_aliases: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    #: Reference to the per-principal budget bucket (ADR-020); defaults to the
    #: agent id so two agents of one owner never share a bucket.
    budget_key: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=text("now()"),
    )

    __table_args__ = (
        CheckConstraint("length(trim(agent_id)) > 0", name="agent_id_not_blank"),
        CheckConstraint("length(trim(owner_sub)) > 0", name="owner_sub_not_blank"),
        CheckConstraint("length(trim(budget_key)) > 0", name="budget_key_not_blank"),
        CheckConstraint("jsonb_typeof(allowed_tools) = 'array'", name="allowed_tools_is_array"),
        CheckConstraint(
            "jsonb_typeof(allowed_route_aliases) = 'array'",
            name="allowed_route_aliases_is_array",
        ),
        Index("ix_agent_registry_tenant_status", "tenant_id", "status"),
    )

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("status", AgentStatus.ACTIVE)
        kwargs.setdefault("allowed_tools", [])
        kwargs.setdefault("allowed_route_aliases", [])
        kwargs.setdefault("budget_key", kwargs.get("agent_id", ""))
        super().__init__(**kwargs)

    @property
    def is_usable(self) -> bool:
        """True while the row is active and inside its expiry window."""
        if self.status != AgentStatus.ACTIVE:
            return False
        return self.expires_at is None or utcnow() < self.expires_at


# ---------------------------------------------------------------------------
# Four-eyes pending approvals
# ---------------------------------------------------------------------------


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
    #: The human an agent initiator acts for (ADR-027). NULL for a human call.
    #: The approver must differ from this too: an owner cannot rubber-stamp
    #: their own agent's mutating call.
    initiator_owner_sub: Mapped[str | None] = mapped_column(String(128), nullable=True)
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
            "approver_id IS NULL OR initiator_owner_sub IS NULL "
            "OR approver_id <> initiator_owner_sub",
            name="four_eyes_owner_separation",
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
        """Four-eyes guard: neither the initiator nor an agent's owner may decide.

        A human initiator has no ``initiator_owner_sub``; an agent's ticket
        carries its owner's subject, and that human is refused as well (ADR-027).
        """
        if not self.is_decidable or actor_id == self.initiator_id:
            return False
        return self.initiator_owner_sub is None or actor_id != self.initiator_owner_sub

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


#: The four-eyes owner column is added in place on databases created before
#: ADR-027; NULL keeps every existing human ticket decidable as before.
FOUR_EYES_OWNER_DDL: Final[tuple[str, ...]] = (
    "ALTER TABLE pending_approvals ADD COLUMN IF NOT EXISTS initiator_owner_sub VARCHAR(128)",
    """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_pending_approvals_four_eyes_owner_separation'
    ) THEN
        ALTER TABLE pending_approvals
            ADD CONSTRAINT ck_pending_approvals_four_eyes_owner_separation
            CHECK (
                approver_id IS NULL OR initiator_owner_sub IS NULL
                OR approver_id <> initiator_owner_sub
            );
    END IF;
END
$$;
""",
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
