"""Encrypted, short-lived payload escrow for pre-production debugging (ADR-005).

The audit ledger stores a SHA-256 digest and nothing else, which is the right
default but leaves an investigator unable to answer "what did the model actually
see?" after an incident. Escrow closes that gap without touching the ledger:

* the writer copies the exact payload that was hashed into a *separate*
  ``payload_escrow`` row as AES-256-GCM ciphertext, bound with AEAD associated
  data to the audit record id, its ``payload_hash``, the tenant and the kind;
* the key is ``PAYLOAD_ESCROW_MASTER_KEY`` when set, otherwise an HKDF-SHA256
  subkey of ``VAULT_MASTER_KEY`` — no key material is committed;
* rows expire on ``PAYLOAD_ESCROW_TTL_SECONDS`` (24 h by default) and the purge
  is a plain row delete, so ``audit_logs`` is never rewritten;
* the whole feature is off by default, and production refuses to start with it
  on (see ``Settings``). This is a PII store, not a production control.

The same rule as the vault applies to this module: never log the plaintext, the
nonce or the key. Callers get the decrypted payload or an error code, and the
decrypt route writes its own ``ESCROW_ACCESSED`` ledger row.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import CursorResult, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import (
    AuditLog,
    EscrowKind,
    PayloadEscrow,
    canonical_payload_bytes,
    hash_payload,
    utcnow,
)
from db.tenancy import TenantIdError, normalise_tenant_id
from settings import get_settings

logger = logging.getLogger(__name__)

_NONCE_BYTES: Final[int] = 12
_AAD_VERSION: Final[str] = "bastion-escrow-v1"


class PayloadEscrowError(RuntimeError):
    """Base class for payload-escrow failures."""


class EscrowPayloadMismatchError(PayloadEscrowError):
    """The payload being escrowed does not hash to the ledger's ``payload_hash``."""


class EscrowNotFoundError(PayloadEscrowError):
    """No escrow row exists for the audit record and tenant."""


class EscrowExpiredError(PayloadEscrowError):
    """The row exists but its retention window has passed."""


class EscrowDecryptionError(PayloadEscrowError):
    """Ciphertext failed authentication or no longer matches its ledger hash."""


@dataclass(frozen=True, slots=True)
class EscrowRecord:
    """A decrypted payload plus the ledger fields that justify trusting it."""

    payload: Any
    audit_log_id: int
    kind: EscrowKind
    payload_hash: str
    expires_at: datetime


class PayloadEscrowCodec:
    """AES-256-GCM encrypt/decrypt bound to one audit record."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("payload escrow key must be exactly 32 bytes (AES-256)")
        self._aes = AESGCM(key)

    @staticmethod
    def _aad(
        *,
        audit_log_id: int,
        payload_hash: str,
        tenant_id: str,
        kind: EscrowKind,
    ) -> bytes:
        """Associated data: a row cannot be moved to another record or tenant."""
        return "|".join(
            (_AAD_VERSION, str(audit_log_id), payload_hash, tenant_id, kind.value)
        ).encode("utf-8")

    def encrypt(
        self,
        *,
        audit_log_id: int,
        payload_hash: str,
        tenant_id: str,
        kind: EscrowKind,
        plaintext: bytes,
    ) -> tuple[bytes, bytes]:
        """Return ``(nonce, ciphertext)`` for one row."""
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = self._aes.encrypt(
            nonce,
            plaintext,
            self._aad(
                audit_log_id=audit_log_id,
                payload_hash=payload_hash,
                tenant_id=tenant_id,
                kind=kind,
            ),
        )
        return nonce, ciphertext

    def decrypt(
        self,
        *,
        audit_log_id: int,
        payload_hash: str,
        tenant_id: str,
        kind: EscrowKind,
        nonce: bytes,
        ciphertext: bytes,
    ) -> bytes:
        """Authenticate and decrypt one row, or raise :class:`EscrowDecryptionError`."""
        if len(nonce) != _NONCE_BYTES:
            raise EscrowDecryptionError("escrow nonce is not 12 bytes")
        try:
            return self._aes.decrypt(
                nonce,
                ciphertext,
                self._aad(
                    audit_log_id=audit_log_id,
                    payload_hash=payload_hash,
                    tenant_id=tenant_id,
                    kind=kind,
                ),
            )
        except InvalidTag as exc:
            raise EscrowDecryptionError(
                "escrow ciphertext failed authentication (tampered or wrong record)"
            ) from exc


def get_payload_escrow_codec() -> PayloadEscrowCodec:
    """Codec wired to the configured key (a fresh subkey derivation per call)."""
    return PayloadEscrowCodec(get_settings().payload_escrow_key_bytes)


def escrow_enabled() -> bool:
    """Whether the pre-production escrow is switched on."""
    return get_settings().payload_escrow_enabled


async def record_payload_escrow(
    session: AsyncSession,
    record: AuditLog,
    payload: Any,
    *,
    kind: EscrowKind = EscrowKind.INPUT_RAW,
    now: datetime | None = None,
) -> PayloadEscrow | None:
    """Encrypt ``payload`` into a new escrow row for ``record``.

    A no-op while ``PAYLOAD_ESCROW_ENABLED`` is false, so the chat path can call
    it unconditionally. The caller must be in the same transaction as
    ``append_audit_event``: the ledger row, the escrow row and the caller's work
    then commit or roll back together.

    Raises :class:`EscrowPayloadMismatchError` if the payload would not reproduce
    the ledger's ``payload_hash`` — the store is only useful if a decrypt can be
    checked against the chain.
    """
    if not escrow_enabled():
        return None
    if record.id is None:  # pragma: no cover - guarded by the append path
        raise PayloadEscrowError("audit record id must be assigned before escrow")
    try:
        tenant = normalise_tenant_id(record.tenant_id)
    except TenantIdError as exc:  # pragma: no cover - the ledger validates first
        raise PayloadEscrowError("escrow requires a valid tenant id") from exc
    if hash_payload(payload) != record.payload_hash:
        raise EscrowPayloadMismatchError(
            "escrowed payload does not reproduce the audit record's payload_hash"
        )

    created = now or utcnow()
    settings = get_settings()
    audit_log_id = int(record.id)
    nonce, ciphertext = get_payload_escrow_codec().encrypt(
        audit_log_id=audit_log_id,
        payload_hash=record.payload_hash,
        tenant_id=tenant,
        kind=kind,
        plaintext=canonical_payload_bytes(payload),
    )
    row = PayloadEscrow(
        audit_log_id=audit_log_id,
        tenant_id=tenant,
        kind=kind,
        payload_hash=record.payload_hash,
        nonce=nonce,
        ciphertext=ciphertext,
        created_at=created,
        expires_at=created + timedelta(seconds=settings.payload_escrow_ttl_seconds),
    )
    session.add(row)
    await session.flush()
    logger.info(
        "Escrowed audit payload",
        extra={
            "audit_log_id": audit_log_id,
            "tenant_id": tenant,
            "kind": kind.value,
        },
    )
    return row


async def read_payload_escrow(
    session: AsyncSession,
    *,
    audit_log_id: int,
    tenant_id: str,
    now: datetime | None = None,
) -> EscrowRecord:
    """Decrypt the escrow row for ``audit_log_id`` within ``tenant_id``.

    A row past ``expires_at`` is refused even before the purge reaches it, so the
    retention window is a property of the store and not only of the sweep.
    """
    try:
        tenant = normalise_tenant_id(tenant_id)
    except TenantIdError as exc:
        raise EscrowNotFoundError("invalid tenant id") from exc
    row = (
        await session.execute(
            select(PayloadEscrow).where(
                PayloadEscrow.audit_log_id == audit_log_id,
                PayloadEscrow.tenant_id == tenant,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise EscrowNotFoundError(f"no escrow row for audit record {audit_log_id}")
    if row.expires_at <= (now or utcnow()):
        raise EscrowExpiredError(f"escrow row for audit record {audit_log_id} has expired")

    plaintext = get_payload_escrow_codec().decrypt(
        audit_log_id=int(row.audit_log_id),
        payload_hash=row.payload_hash,
        tenant_id=row.tenant_id,
        kind=row.kind,
        nonce=row.nonce,
        ciphertext=row.ciphertext,
    )
    payload = _decode_payload(plaintext)
    if hash_payload(payload) != row.payload_hash:
        # The ciphertext authenticated, but the plaintext no longer matches the
        # ledger hash. Report a failed read rather than a plausible-looking one.
        raise EscrowDecryptionError("decrypted payload does not match payload_hash")
    return EscrowRecord(
        payload=payload,
        audit_log_id=int(row.audit_log_id),
        kind=row.kind,
        payload_hash=row.payload_hash,
        expires_at=row.expires_at,
    )


async def purge_expired_escrow(session: AsyncSession, *, now: datetime | None = None) -> int:
    """Delete every escrow row at or past ``expires_at``; return the row count.

    Only ``payload_escrow`` is touched. ``audit_logs`` keeps its record, its
    hashes and its chain link, which is why a purge cannot break verification.
    """
    result = await session.execute(
        delete(PayloadEscrow).where(PayloadEscrow.expires_at <= (now or utcnow()))
    )
    return int(result.rowcount) if isinstance(result, CursorResult) else 0


def _decode_payload(plaintext: bytes) -> Any:
    """Inverse of :func:`canonical_payload_bytes` for the kinds escrowed today."""
    text = plaintext.decode("utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # A raw ``str``/``bytes`` payload is not JSON; return it unchanged so the
        # hash check above still holds.
        return text


__all__ = [
    "EscrowDecryptionError",
    "EscrowExpiredError",
    "EscrowNotFoundError",
    "EscrowPayloadMismatchError",
    "EscrowRecord",
    "PayloadEscrowCodec",
    "PayloadEscrowError",
    "escrow_enabled",
    "get_payload_escrow_codec",
    "purge_expired_escrow",
    "read_payload_escrow",
    "record_payload_escrow",
]
