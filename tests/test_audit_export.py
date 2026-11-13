"""Audit export tests (ADR-005 decision 10).

Signing, paging and segment verification are pure and run everywhere. The
store-backed test needs PostgreSQL (``TEST_DATABASE_URL``) and the
``compliance`` MinIO (``AUDIT_WITNESS_*``), like the witness suite.
"""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from db.audit import append_audit_event
from db.export import (
    AuditExportIntegrityError,
    ExportRecord,
    build_segment,
    export_tenant,
    parse_segment,
    rows_digest,
    segment_key,
    verify_segment,
)
from db.models import GENESIS_HASH, AuditEventType, compute_record_hash
from settings import Settings, get_settings
from tests.conftest import requires_database

ROOT = Path(__file__).resolve().parents[1]
KEY = "test-export-key"

WITNESS_STORE = bool(os.getenv("AUDIT_WITNESS_ENDPOINT"))
requires_witness = pytest.mark.skipif(not WITNESS_STORE, reason="AUDIT_WITNESS_ENDPOINT is not set")


def make_rows(
    count: int, *, tenant: str = "acme", start: int = 1, anchor: str = GENESIS_HASH
) -> list[ExportRecord]:
    """A contiguous run of synthetic records whose hashes truly link."""
    rows: list[ExportRecord] = []
    previous = anchor
    for offset in range(count):
        record_id = start + offset
        timestamp = datetime(2026, 11, 13, 12, 0, offset, tzinfo=UTC)
        payload_hash = f"{record_id:064x}"
        record_hash = compute_record_hash(
            record_id=record_id,
            timestamp=timestamp,
            actor_id="alice",
            event_type=str(AuditEventType.INPUT_RECEIVED),
            payload_hash=payload_hash,
            previous_hash=previous,
        )
        rows.append(
            ExportRecord(
                id=record_id,
                timestamp=timestamp,
                tenant_id=tenant,
                actor_id="alice",
                event_type=str(AuditEventType.INPUT_RECEIVED),
                payload_hash=payload_hash,
                previous_hash=previous,
                record_hash=record_hash,
            )
        )
        previous = record_hash
    return rows


def segment(rows: list[ExportRecord], *, key: str = KEY) -> Any:
    return build_segment(tuple(rows), head_hash=rows[-1].record_hash, key=key)


def test_a_signed_segment_verifies() -> None:
    built = segment(make_rows(3))
    result = verify_segment(built, KEY)
    assert result.ok, result.reason
    assert result.checked == 3
    assert result.links == 2
    assert result.gaps == 0


def test_the_manifest_carries_the_bounds_and_terminal_hash() -> None:
    built = segment(make_rows(3, start=10))
    manifest = built.manifest
    assert (manifest.first_id, manifest.last_id) == (10, 12)
    assert manifest.records == 3
    assert manifest.terminal_hash == built.rows[-1].record_hash
    assert manifest.anchor_hash == GENESIS_HASH
    assert manifest.rows_sha256 == rows_digest(built.rows)


def test_a_tampered_row_is_rejected() -> None:
    built = segment(make_rows(3))
    tampered_row = dataclasses.replace(built.rows[1], payload_hash="f" * 64)
    tampered = dataclasses.replace(built, rows=(*built.rows[:1], tampered_row, *built.rows[2:]))
    assert verify_segment(tampered, KEY).ok is False


def test_a_tampered_manifest_is_rejected() -> None:
    built = segment(make_rows(2))
    tampered = dataclasses.replace(
        built, manifest=dataclasses.replace(built.manifest, terminal_hash="0" * 64)
    )
    result = verify_segment(tampered, KEY)
    assert result.ok is False
    assert "signature" in (result.reason or "")


def test_a_wrong_key_is_rejected() -> None:
    built = segment(make_rows(2))
    assert verify_segment(built, "another-key").ok is False


def test_reordered_rows_are_rejected() -> None:
    built = segment(make_rows(3))
    tampered = dataclasses.replace(built, rows=(built.rows[1], built.rows[0], built.rows[2]))
    assert verify_segment(tampered, KEY).ok is False


def test_a_gap_between_tenants_is_counted_not_verified() -> None:
    rows = make_rows(2)
    later = make_rows(1, start=5, anchor="a" * 64)
    built = segment([*rows, *later])
    result = verify_segment(built, KEY)
    assert result.ok, result.reason
    assert result.checked == 3
    assert result.links == 1
    assert result.gaps == 1


def test_parse_round_trip() -> None:
    built = segment(make_rows(2))
    restored = parse_segment(built.to_json())
    assert restored == built
    assert verify_segment(restored, KEY).ok is True


def test_parse_rejects_a_malformed_document() -> None:
    with pytest.raises(AuditExportIntegrityError):
        parse_segment('{"manifest": {}, "rows": []}')


def test_cli_verifies_a_segment_file(tmp_path: Path) -> None:
    key = get_settings().audit_witness_hmac_secret.get_secret_value()
    built = segment(make_rows(2), key=key)
    path = tmp_path / "segment.json"
    path.write_text(built.to_json(), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "scripts/verify_audit_chain.py", "--segment", str(path), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["checked"] == 2

    path.write_text(built.to_json().replace(built.rows[0].record_hash, "0" * 64), encoding="utf-8")
    tampered = subprocess.run(
        [sys.executable, "scripts/verify_audit_chain.py", "--segment", str(path), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert tampered.returncode == 1, tampered.stderr


# ---------------------------------------------------------------------------
# Database and store
# ---------------------------------------------------------------------------


@pytest.mark.integration
@requires_database
async def test_export_pages_one_tenant_and_keeps_other_tenants_out(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    for index in range(5):
        await append_audit_event(
            session,
            actor_id="alice",
            tenant_id="acme",
            event_type=AuditEventType.INPUT_RECEIVED,
            payload={"prompt": "ACME-SECRET", "index": index},
        )
    for index in range(2):
        await append_audit_event(
            session,
            actor_id="bob",
            tenant_id="globex",
            event_type=AuditEventType.INPUT_RECEIVED,
            payload={"prompt": "GLOBEX-SECRET", "index": index},
        )
    await session.commit()

    published: list[Any] = []

    def fake_put(export: Any, config: Settings) -> str:
        published.append(export)
        return segment_key(export.manifest)

    monkeypatch.setattr("db.export._put_sync", fake_put)
    segments = await export_tenant(session, "acme", page_size=2, settings=get_settings())

    assert len(segments) == 3
    assert [segment.manifest.records for segment in segments] == [2, 2, 1]
    assert published == segments
    ids = [row.id for segment in segments for row in segment.rows]
    assert ids == sorted(ids)
    assert len(set(ids)) == 5
    assert all(row.tenant_id == "acme" for segment in segments for row in segment.rows)
    assert "GLOBEX-SECRET" not in "".join(segment.to_json() for segment in segments)
    assert "ACME-SECRET" not in "".join(segment.to_json() for segment in segments)
    for built in segments:
        assert verify_segment(built, get_settings().audit_witness_hmac_secret.get_secret_value()).ok


@pytest.mark.integration
@pytest.mark.witness_integration
@requires_database
@requires_witness
async def test_export_writes_a_locked_segment_read_back_verifies(session: AsyncSession) -> None:
    for index in range(3):
        await append_audit_event(
            session,
            actor_id="alice",
            tenant_id="acme",
            event_type=AuditEventType.INPUT_RECEIVED,
            payload={"prompt": "EXPORT-SECRET", "index": index},
        )
    await session.commit()

    config = Settings()
    segments = await export_tenant(session, "acme", page_size=2, settings=config)
    assert segments

    import boto3  # only the store-backed test needs the S3 client
    from botocore.config import Config

    assert config.audit_witness_access_key is not None
    assert config.audit_witness_secret_key is not None
    client = boto3.client(
        "s3",
        endpoint_url=config.audit_witness_endpoint,
        region_name=config.audit_witness_region,
        aws_access_key_id=config.audit_witness_access_key.get_secret_value(),
        aws_secret_access_key=config.audit_witness_secret_key.get_secret_value(),
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )
    for built in segments:
        key = segment_key(built.manifest)
        body = client.get_object(Bucket=config.audit_witness_bucket, Key=key)["Body"].read()
        stored = parse_segment(body)
        assert stored == built
        assert verify_segment(stored, config.audit_witness_hmac_secret.get_secret_value()).ok
        assert b"EXPORT-SECRET" not in body
        retention = client.get_object_retention(Bucket=config.audit_witness_bucket, Key=key)
        assert retention["Retention"]["Mode"] == "COMPLIANCE"
