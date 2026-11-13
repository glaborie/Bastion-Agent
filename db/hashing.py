"""Canonical serialisation and SHA-256 hashing for the audit ledger (ADR-005).

Pure functions only: no SQLAlchemy metadata, no clock and no I/O, so a record's
hash can be recomputed from the fields a row carries. ``db.models`` re-exports
these names for callers that import the primitive from there.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Final

#: Hex digest length for SHA-256 / HMAC-SHA256 material.
HASH_HEX_LENGTH: Final[int] = 64


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
        if len(digest) != HASH_HEX_LENGTH:
            raise ValueError(f"{label} must be a {HASH_HEX_LENGTH}-character hex digest")
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
