"""Signed, tenant-partitioned export of the audit ledger (ADR-005 decision 10).

The ledger stays in PostgreSQL; this module pages it into per-tenant segments in
the same write-once store the head witness uses. Each segment carries the
verifiable fields of every record it contains — id, timestamp, tenant, actor,
event, ``payload_hash``, ``previous_hash`` and ``record_hash`` — and a signed
manifest with the segment bounds, the terminal hash and the global head at
export time. No prompt, completion or tool argument is copied: the ledger is
hash-only, and the export must not be the place where plaintext reappears.

``tenant_id`` is the partition key (ADR-015, IDEA-001): a tenant's rows are
exported to their own prefix, so one customer's evidence cannot be served from
another's segment. The chain itself is global, so a tenant segment is a
subsequence of it; verification recomputes every record hash, checks every link
between consecutive exported ids, and reports the gaps that belong to other
tenants rather than pretending they were checked. The global head in the
manifest is what ties the segment back to the ledger and to the witness.
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, NoReturn

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import GENESIS_HASH, AuditLog, canonical_timestamp, compute_record_hash, utcnow
from db.tenancy import TenantIdError, normalise_tenant_id
from db.witness import retention_until, sign_witness, witness_client
from settings import Settings, get_settings

logger = logging.getLogger(__name__)

#: Bumped only if the segment or manifest body changes shape.
EXPORT_VERSION: Final[int] = 1

#: Every object the export may create lives under this prefix.
EXPORT_PREFIX: Final[str] = "export/"

DEFAULT_PAGE_SIZE: Final[int] = 1000

_JSON_SEPARATORS: Final[tuple[str, str]] = (",", ":")


class AuditExportError(RuntimeError):
    """An export could not be produced or verified."""


class AuditExportUnavailable(AuditExportError):
    """The object store is unreachable or refuses the write."""


class AuditExportIntegrityError(AuditExportError):
    """A stored segment is malformed, tampered with or does not match its manifest."""


@dataclass(frozen=True, slots=True)
class ExportRecord:
    """The verifiable fields of one ledger row, with no payload or metadata."""

    id: int
    timestamp: datetime
    tenant_id: str
    actor_id: str
    event_type: str
    payload_hash: str
    previous_hash: str
    record_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": canonical_timestamp(self.timestamp),
            "tenant_id": self.tenant_id,
            "actor_id": self.actor_id,
            "event_type": self.event_type,
            "payload_hash": self.payload_hash,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }

    @classmethod
    def from_row(cls, row: AuditLog) -> ExportRecord:
        return cls(
            id=row.id,
            timestamp=row.timestamp,
            tenant_id=row.tenant_id,
            actor_id=row.actor_id,
            event_type=str(row.event_type),
            payload_hash=row.payload_hash,
            previous_hash=row.previous_hash,
            record_hash=row.record_hash,
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ExportRecord:
        return cls(
            id=int(raw["id"]),
            timestamp=datetime.fromisoformat(str(raw["timestamp"])),
            tenant_id=str(raw["tenant_id"]),
            actor_id=str(raw["actor_id"]),
            event_type=str(raw["event_type"]),
            payload_hash=str(raw["payload_hash"]),
            previous_hash=str(raw["previous_hash"]),
            record_hash=str(raw["record_hash"]),
        )


@dataclass(frozen=True, slots=True)
class SegmentManifest:
    """The signed header of one exported segment."""

    version: int
    tenant_id: str
    first_id: int
    last_id: int
    records: int
    anchor_hash: str
    terminal_hash: str
    head_hash: str
    rows_sha256: str
    created_at: datetime
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "tenant_id": self.tenant_id,
            "first_id": self.first_id,
            "last_id": self.last_id,
            "records": self.records,
            "anchor_hash": self.anchor_hash,
            "terminal_hash": self.terminal_hash,
            "head_hash": self.head_hash,
            "rows_sha256": self.rows_sha256,
            "created_at": canonical_timestamp(self.created_at),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.signed_fields(), "signature": self.signature}


@dataclass(frozen=True, slots=True)
class ExportSegment:
    """One signed segment: its manifest plus the rows it covers."""

    manifest: SegmentManifest
    rows: tuple[ExportRecord, ...]

    def to_json(self) -> str:
        body = {"manifest": self.manifest.to_dict(), "rows": [row.to_dict() for row in self.rows]}
        return json.dumps(body, sort_keys=True, separators=_JSON_SEPARATORS)


@dataclass(frozen=True, slots=True)
class ExportVerification:
    """Outcome of verifying one exported segment against its signature."""

    ok: bool
    checked: int = 0
    links: int = 0
    gaps: int = 0
    first_bad_id: int | None = None
    reason: str | None = None


def rows_digest(rows: tuple[ExportRecord, ...]) -> str:
    """SHA-256 of the canonical rows body, so the manifest binds the rows."""
    body = json.dumps(
        [row.to_dict() for row in rows], sort_keys=True, separators=_JSON_SEPARATORS
    ).encode()
    return hashlib.sha256(body).hexdigest()


def build_segment(
    rows: list[AuditLog] | tuple[ExportRecord, ...],
    *,
    head_hash: str,
    key: str,
    created_at: datetime | None = None,
) -> ExportSegment:
    """Sign one page of ledger rows into a segment."""
    if not rows:
        raise AuditExportError("refusing to export an empty segment")
    records = tuple(
        row if isinstance(row, ExportRecord) else ExportRecord.from_row(row) for row in rows
    )
    tenant = records[0].tenant_id
    if any(record.tenant_id != tenant for record in records):
        raise AuditExportError("a segment may contain one tenant only")
    if any(left.id >= right.id for left, right in itertools.pairwise(records)):
        raise AuditExportError("segment rows must be in strictly increasing id order")

    issued_at = created_at or utcnow()
    digest = rows_digest(records)
    fields: dict[str, Any] = {
        "version": EXPORT_VERSION,
        "tenant_id": tenant,
        "first_id": records[0].id,
        "last_id": records[-1].id,
        "records": len(records),
        "anchor_hash": records[0].previous_hash,
        "terminal_hash": records[-1].record_hash,
        "head_hash": head_hash,
        "rows_sha256": digest,
        "created_at": canonical_timestamp(issued_at),
    }
    manifest = SegmentManifest(
        version=EXPORT_VERSION,
        tenant_id=tenant,
        first_id=records[0].id,
        last_id=records[-1].id,
        records=len(records),
        anchor_hash=records[0].previous_hash,
        terminal_hash=records[-1].record_hash,
        head_hash=head_hash,
        rows_sha256=digest,
        created_at=issued_at,
        signature=sign_witness(fields, key),
    )
    return ExportSegment(manifest=manifest, rows=records)


def parse_segment(payload: str | bytes) -> ExportSegment:
    """Parse a stored segment, rejecting anything the manifest cannot describe."""
    try:
        raw = json.loads(payload)
        manifest_raw = raw["manifest"]
        rows_raw = raw["rows"]
        if not isinstance(manifest_raw, dict) or not isinstance(rows_raw, list):
            raise TypeError("manifest or rows is not an object/list")
        manifest = SegmentManifest(
            version=int(manifest_raw["version"]),
            tenant_id=str(manifest_raw["tenant_id"]),
            first_id=int(manifest_raw["first_id"]),
            last_id=int(manifest_raw["last_id"]),
            records=int(manifest_raw["records"]),
            anchor_hash=str(manifest_raw["anchor_hash"]),
            terminal_hash=str(manifest_raw["terminal_hash"]),
            head_hash=str(manifest_raw["head_hash"]),
            rows_sha256=str(manifest_raw["rows_sha256"]),
            created_at=datetime.fromisoformat(str(manifest_raw["created_at"])),
            signature=str(manifest_raw["signature"]),
        )
        rows = tuple(ExportRecord.from_dict(row) for row in rows_raw)
    except (KeyError, TypeError, ValueError) as exc:
        raise AuditExportIntegrityError(f"exported segment is malformed: {exc}") from exc
    return ExportSegment(manifest=manifest, rows=rows)


def verify_segment(segment: ExportSegment, key: str) -> ExportVerification:
    """Recompute every record hash and every link the segment can prove."""
    manifest = segment.manifest
    expected = sign_witness(manifest.signed_fields(), key)
    if expected != manifest.signature:
        return ExportVerification(ok=False, reason="manifest signature does not verify")

    if rows_digest(segment.rows) != manifest.rows_sha256:
        return ExportVerification(ok=False, reason="rows do not match the manifest digest")
    if manifest.records != len(segment.rows):
        return ExportVerification(ok=False, reason="manifest record count does not match the rows")
    if not segment.rows:
        return ExportVerification(ok=False, reason="segment carries no rows")
    if segment.rows[0].id != manifest.first_id or segment.rows[-1].id != manifest.last_id:
        return ExportVerification(ok=False, reason="manifest bounds do not match the rows")
    if manifest.terminal_hash != segment.rows[-1].record_hash:
        return ExportVerification(ok=False, reason="terminal hash does not match the last row")

    checked = 0
    links = 0
    gaps = 0
    previous: ExportRecord | None = None
    for record in segment.rows:
        if record.tenant_id != manifest.tenant_id:
            return ExportVerification(
                ok=False,
                checked=checked,
                first_bad_id=record.id,
                reason="record does not belong to the manifest tenant",
            )
        if previous is not None:
            if record.id <= previous.id:
                return ExportVerification(
                    ok=False,
                    checked=checked,
                    first_bad_id=record.id,
                    reason="rows are not in strictly increasing id order",
                )
            if record.id == previous.id + 1:
                if record.previous_hash != previous.record_hash:
                    return ExportVerification(
                        ok=False,
                        checked=checked,
                        first_bad_id=record.id,
                        reason="previous_hash does not link to the preceding exported row",
                    )
                links += 1
            else:
                gaps += 1
        recomputed = compute_record_hash(
            record_id=record.id,
            timestamp=record.timestamp,
            actor_id=record.actor_id,
            event_type=record.event_type,
            payload_hash=record.payload_hash,
            previous_hash=record.previous_hash,
        )
        if recomputed != record.record_hash:
            return ExportVerification(
                ok=False,
                checked=checked,
                first_bad_id=record.id,
                reason="record_hash does not match record contents",
            )
        checked += 1
        previous = record
    return ExportVerification(ok=True, checked=checked, links=links, gaps=gaps)


def segment_key(manifest: SegmentManifest) -> str:
    """Append-only key: one object per segment, ordered by id range."""
    return (
        f"{EXPORT_PREFIX}{manifest.tenant_id}/{manifest.first_id:012d}-{manifest.last_id:012d}.json"
    )


def _settings(settings: Settings | None) -> Settings:
    return settings or get_settings()


def _put_sync(segment: ExportSegment, config: Settings) -> str:
    manifest = segment.manifest
    key = segment_key(manifest)
    client = witness_client(config)
    try:
        client.put_object(
            Bucket=config.audit_witness_bucket,
            Key=key,
            Body=segment.to_json().encode("utf-8"),
            ContentType="application/json",
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retention_until(
                manifest.created_at, config.audit_witness_retention_years
            ),
        )
    except (BotoCoreError, ClientError) as exc:
        _unavailable("writing the audit export", exc)
    return key


def _unavailable(action: str, exc: Exception) -> NoReturn:
    raise AuditExportUnavailable(f"{action} failed: {exc}") from exc


async def _global_head(session: AsyncSession) -> str:
    result = await session.execute(
        select(AuditLog.record_hash).order_by(AuditLog.id.desc()).limit(1)
    )
    return result.scalar_one_or_none() or GENESIS_HASH


async def export_tenant(
    session: AsyncSession,
    tenant_id: str,
    *,
    page_size: int = DEFAULT_PAGE_SIZE,
    settings: Settings | None = None,
    created_at: datetime | None = None,
) -> list[ExportSegment]:
    """Page one tenant's ledger rows into signed, locked segments."""
    if page_size <= 0:
        raise ValueError("page_size must be a positive integer")
    try:
        tenant = normalise_tenant_id(tenant_id)
    except TenantIdError as exc:
        raise AuditExportError(f"invalid tenant id: {exc}") from exc

    config = _settings(settings)
    key = config.audit_witness_hmac_secret.get_secret_value()
    head_hash = await _global_head(session)
    issued_at = created_at or utcnow()

    segments: list[ExportSegment] = []
    cursor = 0
    while True:
        result = await session.execute(
            select(AuditLog)
            .where(AuditLog.tenant_id == tenant, AuditLog.id > cursor)
            .order_by(AuditLog.id.asc())
            .limit(page_size)
        )
        rows = list(result.scalars())
        if not rows:
            break
        segment = build_segment(rows, head_hash=head_hash, key=key, created_at=issued_at)
        stored_key = await asyncio.to_thread(_put_sync, segment, config)
        logger.info(
            "Audit export segment published",
            extra={
                "tenant_id": tenant,
                "key": stored_key,
                "first_id": segment.manifest.first_id,
                "last_id": segment.manifest.last_id,
                "records": segment.manifest.records,
            },
        )
        segments.append(segment)
        cursor = rows[-1].id
    return segments


async def export_ledger(
    session: AsyncSession,
    *,
    tenants: list[str] | None = None,
    page_size: int = DEFAULT_PAGE_SIZE,
    settings: Settings | None = None,
) -> list[ExportSegment]:
    """Export every tenant, or the ones named, in one run."""
    if tenants is None:
        result = await session.execute(
            select(AuditLog.tenant_id).distinct().order_by(AuditLog.tenant_id)
        )
        tenants = list(result.scalars())
    segments: list[ExportSegment] = []
    for tenant in tenants:
        segments.extend(
            await export_tenant(session, tenant, page_size=page_size, settings=settings)
        )
    return segments


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "EXPORT_PREFIX",
    "EXPORT_VERSION",
    "AuditExportError",
    "AuditExportIntegrityError",
    "AuditExportUnavailable",
    "ExportRecord",
    "ExportSegment",
    "ExportVerification",
    "SegmentManifest",
    "build_segment",
    "export_ledger",
    "export_tenant",
    "parse_segment",
    "rows_digest",
    "segment_key",
    "verify_segment",
]
