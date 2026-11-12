"""Write-once witness of the audit chain head (ADR-005 decision 9).

The ledger alone proves its records agree with each other; an attacker who can
write the database can recompute the whole chain. The witness closes that gap by
copying the head hash, the id range and the row count to object storage that the
application can append to but cannot rewrite: a versioned bucket with
``COMPLIANCE`` object lock and a server-enforced 7-year retention.

Only hashes and counters leave the database. The object carries no prompt,
completion, tool argument, actor or plaintext PII, matching the ledger's
hash-only posture (``THREAT_MODEL.md`` T10).

The signing key is HMAC-SHA256 over a canonical JSON body, so a witness copied
between scopes or edited in place fails verification even when the store itself
is compromised. Like the retention it protects, the key is an operational
secret: it is not a substitute for the store's own access control.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, NoReturn

from botocore.exceptions import BotoCoreError, ClientError

from db.audit import ChainVerification
from db.models import canonical_timestamp, utcnow
from settings import Settings, get_settings

logger = logging.getLogger(__name__)

#: Bumped only if the signed body changes shape; old witnesses stay verifiable
#: with the version they were written under.
WITNESS_VERSION: Final[int] = 1

#: The ledger is one global chain today. Per-tenant witnesses are IDEA-001's
#: decision to make, because it owns the tenant dimension.
DEFAULT_SCOPE: Final[str] = "global"

#: Every object the application may create lives under this prefix.
WITNESS_PREFIX: Final[str] = "witness/"

_JSON_SEPARATORS: Final[tuple[str, str]] = (",", ":")

#: Append-only key name produced by :func:`object_key`. Listing filters on it so
#: an unrelated object under the prefix cannot shadow the newest witness.
WITNESS_KEY_RE: Final[re.Pattern[str]] = re.compile(r"^\d{8}T\d{6}\d{6}Z-\d{12}\.json$")


class AuditWitnessError(RuntimeError):
    """A witness could not be produced, read or compared."""


class AuditWitnessUnavailable(AuditWitnessError):
    """The object store is unreachable or refuses the operation."""


class AuditWitnessIntegrityError(AuditWitnessError):
    """A stored witness does not match its signature or its own body."""


@dataclass(frozen=True, slots=True)
class AuditWitness:
    """One signed statement about the ledger at a point in time."""

    version: int
    scope: str
    first_id: int | None
    last_id: int | None
    records: int
    head_hash: str
    created_at: datetime
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        """The exact body the signature covers, in canonical JSON form."""
        return {
            "version": self.version,
            "scope": self.scope,
            "first_id": self.first_id,
            "last_id": self.last_id,
            "records": self.records,
            "head_hash": self.head_hash,
            "created_at": canonical_timestamp(self.created_at),
        }

    def to_json(self) -> str:
        body = {**self.signed_fields(), "signature": self.signature}
        return json.dumps(body, sort_keys=True, separators=_JSON_SEPARATORS)


@dataclass(frozen=True, slots=True)
class WitnessComparison:
    """Result of checking a live verification against the latest witness."""

    ok: bool
    reason: str | None = None
    witness: AuditWitness | None = None


def canonical_witness_bytes(fields: dict[str, Any]) -> bytes:
    """Serialise a witness body deterministically for HMAC input."""
    return json.dumps(fields, sort_keys=True, separators=_JSON_SEPARATORS).encode()


def sign_witness(fields: dict[str, Any], key: str) -> str:
    """HMAC-SHA256 a canonical witness body."""
    return hmac.new(
        key.encode("utf-8"), canonical_witness_bytes(fields), hashlib.sha256
    ).hexdigest()


def verify_witness_signature(witness: AuditWitness, key: str) -> bool:
    """Constant-time check that the witness body carries the expected HMAC."""
    expected = sign_witness(witness.signed_fields(), key)
    return hmac.compare_digest(expected, witness.signature)


def retention_until(created_at: datetime, years: int) -> datetime:
    """Return the object-lock deadline, clamping 29 February to the 28th."""
    if years <= 0:
        raise ValueError("retention years must be positive")
    try:
        return created_at.replace(year=created_at.year + years)
    except ValueError:  # 29 February in a non-leap target year
        return created_at.replace(year=created_at.year + years, day=28)


def build_witness(
    verification: ChainVerification,
    *,
    scope: str = DEFAULT_SCOPE,
    key: str,
    created_at: datetime | None = None,
) -> AuditWitness:
    """Build a signed witness from a successful chain verification."""
    if not verification.ok or verification.head_hash is None:
        raise AuditWitnessError("refusing to witness a ledger whose chain does not verify")
    issued_at = created_at or utcnow()
    fields = {
        "version": WITNESS_VERSION,
        "scope": scope,
        "first_id": verification.first_id,
        "last_id": verification.last_id,
        "records": verification.checked,
        "head_hash": verification.head_hash,
        "created_at": canonical_timestamp(issued_at),
    }
    return AuditWitness(
        version=WITNESS_VERSION,
        scope=scope,
        first_id=verification.first_id,
        last_id=verification.last_id,
        records=verification.checked,
        head_hash=verification.head_hash,
        created_at=issued_at,
        signature=sign_witness(fields, key),
    )


def object_key(witness: AuditWitness) -> str:
    """Append-only key: one object per witness, ordered by timestamp."""
    marker = witness.last_id if witness.last_id is not None else 0
    stamp = witness.created_at.astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{WITNESS_PREFIX}{witness.scope}/{stamp}-{marker:012d}.json"


def compare(verification: ChainVerification, witness: AuditWitness) -> WitnessComparison:
    """Compare a live ledger verification with a stored witness."""
    if not verification.ok:
        return WitnessComparison(
            ok=False,
            reason=verification.reason or "the ledger chain does not verify",
            witness=witness,
        )
    if verification.head_hash != witness.head_hash:
        return WitnessComparison(
            ok=False,
            reason=(
                "the ledger head does not match the witness "
                f"({verification.head_hash} != {witness.head_hash})"
            ),
            witness=witness,
        )
    records = verification.checked
    if records != witness.records or verification.last_id != witness.last_id:
        return WitnessComparison(
            ok=False,
            reason=(
                "the ledger covers a different id range than the witness "
                f"({verification.first_id}..{verification.last_id}/{records} vs "
                f"{witness.first_id}..{witness.last_id}/{witness.records})"
            ),
            witness=witness,
        )
    return WitnessComparison(ok=True, witness=witness)


def _settings(settings: Settings | None) -> Settings:
    return settings or get_settings()


def _credentials(config: Settings) -> tuple[str, str]:
    access = config.audit_witness_access_key
    secret = config.audit_witness_secret_key
    if access is None or secret is None:
        raise AuditWitnessUnavailable(
            "AUDIT_WITNESS_ACCESS_KEY and AUDIT_WITNESS_SECRET_KEY are required to use "
            "the audit witness"
        )
    return access.get_secret_value(), secret.get_secret_value()


def _client(config: Settings) -> Any:
    import boto3  # imported lazily so the rest of the ledger works without an S3 call
    from botocore.config import Config

    access_key, secret_key = _credentials(config)
    return boto3.client(
        "s3",
        endpoint_url=config.audit_witness_endpoint,
        region_name=config.audit_witness_region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )


def _unavailable(action: str, exc: Exception) -> NoReturn:
    raise AuditWitnessUnavailable(f"{action} failed: {exc}") from exc


def _put_sync(witness: AuditWitness, config: Settings) -> str:
    key = object_key(witness)
    client = _client(config)
    try:
        client.put_object(
            Bucket=config.audit_witness_bucket,
            Key=key,
            Body=witness.to_json().encode("utf-8"),
            ContentType="application/json",
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retention_until(
                witness.created_at, config.audit_witness_retention_years
            ),
        )
    except (BotoCoreError, ClientError) as exc:
        _unavailable("writing the audit witness", exc)
    return key


def _get_sync(config: Settings, scope: str) -> AuditWitness:
    client = _client(config)
    prefix = f"{WITNESS_PREFIX}{scope}/"
    try:
        keys = [
            item["Key"]
            for page in client.get_paginator("list_objects_v2").paginate(
                Bucket=config.audit_witness_bucket, Prefix=prefix
            )
            for item in page.get("Contents", [])
            if WITNESS_KEY_RE.match(item.get("Key", "").rsplit("/", 1)[-1])
        ]
        if not keys:
            raise AuditWitnessUnavailable(f"no audit witness is stored under {prefix}")
        body = client.get_object(Bucket=config.audit_witness_bucket, Key=max(keys))["Body"].read()
    except (BotoCoreError, ClientError) as exc:
        _unavailable("reading the audit witness", exc)

    try:
        parsed = json.loads(body)
        created_at = datetime.fromisoformat(parsed["created_at"])
        witness = AuditWitness(
            version=int(parsed["version"]),
            scope=str(parsed["scope"]),
            first_id=parsed["first_id"],
            last_id=parsed["last_id"],
            records=int(parsed["records"]),
            head_hash=str(parsed["head_hash"]),
            created_at=created_at,
            signature=str(parsed["signature"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AuditWitnessIntegrityError(f"stored witness is malformed: {exc}") from exc

    expected_keys = {"version", "scope", "first_id", "last_id", "records", "head_hash"}
    if set(parsed) - expected_keys - {"created_at", "signature"}:
        raise AuditWitnessIntegrityError("stored witness carries unexpected fields")
    if witness.scope != scope:
        raise AuditWitnessIntegrityError("stored witness scope does not match its prefix")
    if not verify_witness_signature(witness, config.audit_witness_hmac_secret.get_secret_value()):
        raise AuditWitnessIntegrityError("stored witness signature does not verify")
    return witness


async def publish_witness(
    verification: ChainVerification,
    *,
    scope: str = DEFAULT_SCOPE,
    settings: Settings | None = None,
    created_at: datetime | None = None,
) -> AuditWitness:
    """Write one signed witness and return it."""
    config = _settings(settings)
    witness = build_witness(
        verification,
        scope=scope,
        key=config.audit_witness_hmac_secret.get_secret_value(),
        created_at=created_at,
    )
    key = await asyncio.to_thread(_put_sync, witness, config)
    logger.info(
        "Audit witness published",
        extra={"key": key, "head_hash": witness.head_hash, "records": witness.records},
    )
    return witness


async def latest_witness(
    *, scope: str = DEFAULT_SCOPE, settings: Settings | None = None
) -> AuditWitness:
    """Read and verify the newest witness for ``scope``."""
    return await asyncio.to_thread(_get_sync, _settings(settings), scope)


async def witness_matches(
    verification: ChainVerification,
    *,
    scope: str = DEFAULT_SCOPE,
    settings: Settings | None = None,
) -> WitnessComparison:
    """Fetch the latest witness and compare it with a live verification."""
    witness = await latest_witness(scope=scope, settings=settings)
    return compare(verification, witness)


__all__ = [
    "DEFAULT_SCOPE",
    "WITNESS_PREFIX",
    "AuditWitness",
    "AuditWitnessError",
    "AuditWitnessIntegrityError",
    "AuditWitnessUnavailable",
    "WitnessComparison",
    "build_witness",
    "canonical_witness_bytes",
    "compare",
    "latest_witness",
    "object_key",
    "publish_witness",
    "retention_until",
    "sign_witness",
    "verify_witness_signature",
    "witness_matches",
]
