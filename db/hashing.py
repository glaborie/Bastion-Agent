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

#: Current record-hash preimage version. v1 covers six fields; v2 also covers
#: ``hash_version`` and the canonical ``metadata_json`` digest (ADR-005
#: decision 2), so four-eyes keys cannot be edited without breaking the chain.
#: v3 appends the actor triple (ADR-027), so an agent's rows cannot be
#: relabelled as a human's without breaking verification.
CURRENT_HASH_VERSION: Final[int] = 3

#: ``actor_type`` values a ledger row can carry.
ACTOR_TYPES: Final[frozenset[str]] = frozenset({"human", "agent"})


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
    hash_version: int = 1,
    metadata_hash: str | None = None,
    actor_type: str = "human",
    agent_id: str | None = None,
    owner_sub: str | None = None,
) -> str:
    """Compute ``record_hash`` exactly as specified in HANDOVER_SPEC §3.5.

    v1 (pre-2026-11-16) hashes the original six fields. v2 appends the version
    and the SHA-256 of the canonical ``metadata_json`` bytes, so editing an
    approver, initiator or outcome breaks verification while v1 rows keep
    verifying with their original preimage (ADR-005 decision 2). v3 appends the
    actor triple (``actor_type``, ``agent_id``, ``owner_sub``) so an agent's
    record cannot be edited to read as a human's (ADR-027).
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
    if hash_version == 1:
        if metadata_hash is not None:
            raise ValueError("v1 records carry no metadata_hash")
        if actor_type != "human" or agent_id is not None or owner_sub is not None:
            raise ValueError("v1 records carry no actor triple")
    elif hash_version == 2:
        if metadata_hash is None or len(metadata_hash) != HASH_HEX_LENGTH:
            raise ValueError(
                f"v{hash_version} records require a {HASH_HEX_LENGTH}-character metadata_hash"
            )
        if actor_type != "human" or agent_id is not None or owner_sub is not None:
            raise ValueError("v2 records carry no actor triple")
        material = "|".join((material, str(hash_version), metadata_hash))
    elif hash_version == CURRENT_HASH_VERSION:
        if metadata_hash is None or len(metadata_hash) != HASH_HEX_LENGTH:
            raise ValueError(
                f"v{hash_version} records require a {HASH_HEX_LENGTH}-character metadata_hash"
            )
        if actor_type not in ACTOR_TYPES:
            raise ValueError(f"unsupported actor_type {actor_type!r}")
        if actor_type == "agent" and not agent_id:
            raise ValueError("agent records require agent_id")
        if actor_type == "human" and (agent_id is not None or owner_sub is not None):
            raise ValueError("human records carry no agent_id or owner_sub")
        material = "|".join(
            (
                material,
                str(hash_version),
                metadata_hash,
                actor_type,
                agent_id or "",
                owner_sub or "",
            )
        )
    else:
        raise ValueError(f"unsupported record hash version {hash_version}")
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
