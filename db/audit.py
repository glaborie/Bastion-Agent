"""Transactional writer and verifier for the cryptographic audit chain.

Every append takes a PostgreSQL transaction-scoped advisory lock, reads the tail
hash, allocates the next identifier, and writes the chained record. That makes
the chain strictly serialised even under concurrent writers, without relying on
``SERIALIZABLE`` isolation for the whole application.

Callers are expected to append audit records **inside the same transaction** as
the action they describe, so that the action and its audit trail either both
commit or both roll back.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from db.escrow import record_payload_escrow
from db.models import (
    AUDIT_CHAIN_LOCK_ID,
    AUDIT_LOG_ID_SEQUENCE,
    GENESIS_HASH,
    AuditEventType,
    AuditLog,
    EscrowKind,
    compute_record_hash,
    hash_payload,
    utcnow,
)
from db.tenancy import TenantIdError, normalise_tenant_id

logger = logging.getLogger(__name__)

_ALLOCATE_ID = text("SELECT nextval(CAST(:sequence AS regclass))")
_ACQUIRE_CHAIN_LOCK = text("SELECT pg_advisory_xact_lock(:lock_id)")
_LATEST_HASH = select(AuditLog.record_hash).order_by(AuditLog.id.desc()).limit(1)


class AuditChainError(RuntimeError):
    """Raised when the audit chain cannot be extended safely."""


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """Outcome of a full (or partial) chain verification pass."""

    ok: bool
    checked: int
    first_bad_id: int | None = None
    reason: str | None = None

    def __bool__(self) -> bool:
        return self.ok


async def append_audit_event(
    session: AsyncSession,
    *,
    actor_id: str,
    tenant_id: str,
    event_type: AuditEventType,
    session_id: str | None = None,
    payload: Any | None = None,
    payload_hash: str | None = None,
    metadata_json: Mapping[str, Any] | None = None,
    timestamp: datetime | None = None,
    escrow: bool = False,
    escrow_kind: EscrowKind = EscrowKind.INPUT_RAW,
) -> AuditLog:
    """Append one hash-chained audit record and return it (flushed, not committed).

    Pass either ``payload`` (hashed canonically here) or a pre-computed
    ``payload_hash`` — never raw PII in ``metadata_json``.

    ``escrow=True`` also writes an encrypted copy of ``payload`` to
    ``payload_escrow`` in the same transaction (ADR-005 decisions 7-8). It is a
    no-op unless ``PAYLOAD_ESCROW_ENABLED`` is on, and it requires ``payload``:
    the escrow must be able to reproduce the ledger's digest. ``escrow_kind``
    distinguishes the raw request from the delivered answer.
    """
    if not actor_id or not actor_id.strip():
        raise AuditChainError("actor_id is required for every audit record")
    try:
        tenant = normalise_tenant_id(tenant_id)
    except TenantIdError as exc:
        raise AuditChainError("tenant_id is required for every audit record") from exc
    if payload is not None and payload_hash is not None:
        raise AuditChainError("pass either payload or payload_hash, not both")
    if escrow and payload is None:
        raise AuditChainError("escrow requires the payload itself, not only its hash")

    resolved_payload_hash = (
        payload_hash
        if payload_hash is not None
        else hash_payload(payload if payload is not None else {})
    )
    issued_at = timestamp or utcnow()

    # Serialise chain extension for the remainder of this transaction.
    await session.execute(_ACQUIRE_CHAIN_LOCK, {"lock_id": AUDIT_CHAIN_LOCK_ID})

    previous_hash = (await session.execute(_LATEST_HASH)).scalar_one_or_none() or GENESIS_HASH

    record_id = (
        await session.execute(_ALLOCATE_ID, {"sequence": AUDIT_LOG_ID_SEQUENCE.name})
    ).scalar_one()

    record = AuditLog(
        id=int(record_id),
        timestamp=issued_at,
        session_id=session_id,
        tenant_id=tenant,
        actor_id=actor_id,
        event_type=event_type,
        payload_hash=resolved_payload_hash,
        metadata_json=dict(metadata_json or {}),
        previous_hash=previous_hash,
        record_hash="",
    )
    record.record_hash = compute_record_hash(
        record_id=record.id,
        timestamp=record.timestamp,
        actor_id=record.actor_id,
        event_type=str(record.event_type),
        payload_hash=record.payload_hash,
        previous_hash=record.previous_hash,
    )

    session.add(record)
    await session.flush()
    if escrow and payload is not None:
        await record_payload_escrow(session, record, payload, kind=escrow_kind)
    return record


async def verify_audit_chain(
    session: AsyncSession,
    *,
    limit: int | None = None,
) -> ChainVerification:
    """Walk the ledger in id order and check every hash and linkage.

    ``limit`` verifies only the most recent ``limit`` records, which is useful for
    cheap continuous integrity checks on large ledgers.
    """
    if limit is not None and limit <= 0:
        raise ValueError("limit must be a positive integer")

    statement = select(AuditLog).order_by(AuditLog.id.asc())
    if limit is not None:
        tail_ids = select(AuditLog.id).order_by(AuditLog.id.desc()).limit(limit).subquery()
        statement = (
            select(AuditLog)
            .where(AuditLog.id.in_(select(tail_ids.c.id)))
            .order_by(AuditLog.id.asc())
        )

    result = await session.execute(statement)
    records = list(result.scalars())

    if not records:
        return ChainVerification(ok=True, checked=0)

    # A full scan must begin at the genesis hash. A windowed scan cannot prove
    # the link into the window, so it trusts the first record's own
    # ``previous_hash`` as its anchor and validates every link after that.
    expected_previous = records[0].previous_hash if limit is not None else GENESIS_HASH

    checked = 0
    for record in records:
        if record.previous_hash != expected_previous:
            return ChainVerification(
                ok=False,
                checked=checked,
                first_bad_id=record.id,
                reason="previous_hash does not link to the preceding record",
            )
        if not record.verify():
            return ChainVerification(
                ok=False,
                checked=checked,
                first_bad_id=record.id,
                reason="record_hash does not match record contents",
            )
        expected_previous = record.record_hash
        checked += 1

    logger.debug("Audit chain verified", extra={"checked": checked, "windowed": limit is not None})
    return ChainVerification(ok=True, checked=checked)
