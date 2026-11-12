"""Audit witness tests (ADR-005 decision 9).

Pure signing, retention and comparison run everywhere. The store-backed tests
need both PostgreSQL (``TEST_DATABASE_URL``) and the ``compliance`` MinIO
(``AUDIT_WITNESS_*``); they are skipped otherwise so a laptop without the
profile still runs the rest of the suite.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from db.audit import ChainVerification, append_audit_event, verify_audit_chain
from db.models import GENESIS_HASH, AuditEventType
from db.witness import (
    AuditWitnessError,
    AuditWitnessIntegrityError,
    AuditWitnessUnavailable,
    build_witness,
    compare,
    latest_witness,
    object_key,
    publish_witness,
    retention_until,
    sign_witness,
    verify_witness_signature,
    witness_matches,
)
from settings import Settings
from tests.conftest import TEST_DATABASE_URL, requires_database

ROOT = Path(__file__).resolve().parents[1]

WITNESS_STORE = bool(os.getenv("AUDIT_WITNESS_ENDPOINT"))
requires_witness = pytest.mark.skipif(not WITNESS_STORE, reason="AUDIT_WITNESS_ENDPOINT is not set")


def witness_settings() -> Settings:
    """Settings for the live store, refusing to silently use defaults."""
    if not WITNESS_STORE:
        pytest.skip("AUDIT_WITNESS_ENDPOINT is not set")
    return Settings()


def s3_client(access_key: str, secret_key: str, endpoint: str | None = None) -> Any:
    return boto3.client(
        "s3",
        endpoint_url=endpoint or witness_settings().audit_witness_endpoint,
        region_name=witness_settings().audit_witness_region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def app_client() -> Any:
    config = witness_settings()
    assert config.audit_witness_access_key is not None
    assert config.audit_witness_secret_key is not None
    return s3_client(
        config.audit_witness_access_key.get_secret_value(),
        config.audit_witness_secret_key.get_secret_value(),
    )


def root_client() -> Any:
    user = os.getenv("MINIO_ROOT_USER")
    password = os.getenv("MINIO_ROOT_PASSWORD")
    assert user and password, "MINIO_ROOT_USER/MINIO_ROOT_PASSWORD are not set"
    return s3_client(user, password)


def scope_name() -> str:
    return f"test-{uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Pure behaviour
# ---------------------------------------------------------------------------


def test_retention_until_is_seven_years_and_clamps_leap_day() -> None:
    assert retention_until(datetime(2026, 11, 12, tzinfo=UTC), 7) == datetime(
        2033, 11, 12, tzinfo=UTC
    )
    assert retention_until(datetime(2028, 2, 29, tzinfo=UTC), 2) == datetime(
        2030, 2, 28, tzinfo=UTC
    )
    with pytest.raises(ValueError):
        retention_until(datetime(2026, 11, 12, tzinfo=UTC), 0)


def test_witness_signature_covers_the_whole_body() -> None:
    verification = ChainVerification(
        ok=True,
        checked=3,
        first_id=1,
        last_id=3,
        head_hash="a" * 64,
    )
    witness = build_witness(
        verification, key="k" * 32, created_at=datetime(2026, 11, 12, tzinfo=UTC)
    )
    assert verify_witness_signature(witness, "k" * 32)
    assert not verify_witness_signature(witness, "other-key")
    assert sign_witness(witness.signed_fields(), "k" * 32) == witness.signature
    assert json.loads(witness.to_json())["head_hash"] == "a" * 64


def test_object_key_is_scoped_and_append_only() -> None:
    verification = ChainVerification(ok=True, checked=3, first_id=1, last_id=9, head_hash="b" * 64)
    first = build_witness(
        verification, scope="global", key="k", created_at=datetime(2026, 11, 12, tzinfo=UTC)
    )
    later = build_witness(
        verification,
        scope="global",
        key="k",
        created_at=datetime(2026, 11, 12, 0, 0, 1, tzinfo=UTC),
    )
    assert object_key(first).startswith("witness/global/")
    assert object_key(first) < object_key(later)


def test_build_refuses_a_broken_chain() -> None:
    broken = ChainVerification(ok=False, checked=0, first_bad_id=4, reason="boom")
    with pytest.raises(AuditWitnessError, match="does not verify"):
        build_witness(broken, key="k")


def test_compare_detects_a_divergent_head_and_range() -> None:
    witness = build_witness(
        ChainVerification(ok=True, checked=2, first_id=1, last_id=2, head_hash="c" * 64),
        key="k",
    )
    same = ChainVerification(ok=True, checked=2, first_id=1, last_id=2, head_hash="c" * 64)
    assert compare(same, witness).ok

    other_head = ChainVerification(ok=True, checked=2, first_id=1, last_id=2, head_hash="d" * 64)
    assert not compare(other_head, witness).ok

    shorter = ChainVerification(ok=True, checked=1, first_id=1, last_id=1, head_hash="c" * 64)
    assert not compare(shorter, witness).ok


# ---------------------------------------------------------------------------
# Store-backed behaviour
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.witness_integration
@requires_database
@requires_witness
async def test_publish_then_read_back_reports_the_same_head(session: AsyncSession) -> None:
    for index in range(3):
        await append_audit_event(
            session,
            actor_id="alice",
            tenant_id="acme",
            event_type=AuditEventType.INPUT_RECEIVED,
            payload={"prompt": "TOP-SECRET-PROMPT", "index": index},
        )
    await session.commit()

    config = witness_settings()
    scope = scope_name()
    verification = await verify_audit_chain(session)
    witness = await publish_witness(verification, scope=scope, settings=config)
    assert witness.records == 3
    assert witness.last_id == verification.last_id
    assert witness.head_hash == verification.head_hash

    stored = await latest_witness(scope=scope, settings=config)
    assert stored == witness
    assert compare(verification, stored).ok

    body = json.loads(
        app_client()
        .get_object(Bucket=config.audit_witness_bucket, Key=object_key(witness))["Body"]
        .read()
    )
    assert set(body) == {
        "version",
        "scope",
        "first_id",
        "last_id",
        "records",
        "head_hash",
        "created_at",
        "signature",
    }
    assert "TOP-SECRET-PROMPT" not in json.dumps(body)
    assert "prompt" not in body


@pytest.mark.witness_integration
@requires_witness
def test_bucket_is_versioned_with_compliance_retention() -> None:
    config = witness_settings()
    client = root_client()
    versioning = client.get_bucket_versioning(Bucket=config.audit_witness_bucket)
    assert versioning["Status"] == "Enabled"
    rule = client.get_object_lock_configuration(Bucket=config.audit_witness_bucket)[
        "ObjectLockConfiguration"
    ]["Rule"]
    assert rule["DefaultRetention"] == {
        "Mode": "COMPLIANCE",
        "Years": config.audit_witness_retention_years,
    }


@pytest.mark.integration
@pytest.mark.witness_integration
@requires_database
@requires_witness
async def test_app_credentials_cannot_delete_or_weaken_retention(
    session: AsyncSession,
) -> None:
    await append_audit_event(
        session,
        actor_id="alice",
        tenant_id="acme",
        event_type=AuditEventType.INPUT_RECEIVED,
        payload={"n": 1},
    )
    await session.commit()
    config = witness_settings()
    scope = scope_name()
    verification = await verify_audit_chain(session)
    witness = await publish_witness(verification, scope=scope, settings=config)
    key = object_key(witness)
    client = app_client()

    with pytest.raises(ClientError) as denied:
        client.delete_object(Bucket=config.audit_witness_bucket, Key=key)
    assert denied.value.response["Error"]["Code"] in {"AccessDenied", "AccessDeniedException"}

    versions = client.list_object_versions(Bucket=config.audit_witness_bucket, Prefix=key)[
        "Versions"
    ]
    original = versions[0]["VersionId"]

    # An overwrite is a new version, not a replacement: the retained version
    # survives and remains listed. Retention is what forbids the replacement.
    client.put_object(
        Bucket=config.audit_witness_bucket,
        Key=key,
        Body=b"{}",
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=retention_until(datetime.now(UTC), 7),
    )
    after = client.list_object_versions(Bucket=config.audit_witness_bucket, Prefix=key)["Versions"]
    assert {version["VersionId"] for version in after} >= {original}

    for name, call in {
        "object lock": lambda: client.put_object_lock_configuration(
            Bucket=config.audit_witness_bucket,
            ObjectLockConfiguration={"ObjectLockEnabled": "Enabled"},
        ),
        "versioning": lambda: client.put_bucket_versioning(
            Bucket=config.audit_witness_bucket,
            VersioningConfiguration={"Status": "Suspended"},
        ),
        "bucket policy": lambda: client.put_bucket_policy(
            Bucket=config.audit_witness_bucket, Policy="{}"
        ),
    }.items():
        with pytest.raises(ClientError) as refused:
            call()
        assert refused.value.response["Error"]["Code"] in {
            "AccessDenied",
            "AccessDeniedException",
        }, name


@pytest.mark.integration
@pytest.mark.witness_integration
@requires_database
@requires_witness
async def test_witness_catches_a_chain_recomputed_in_the_database(
    session: AsyncSession,
) -> None:
    records = []
    for index in range(3):
        records.append(
            await append_audit_event(
                session,
                actor_id="alice",
                tenant_id="acme",
                event_type=AuditEventType.INPUT_RECEIVED,
                payload={"index": index},
            )
        )
    await session.commit()

    config = witness_settings()
    scope = scope_name()
    witness = await publish_witness(await verify_audit_chain(session), scope=scope, settings=config)

    # Removing the tail leaves a chain that still verifies: every surviving link
    # is intact. Only the stored witness notices that the head moved.
    await session.execute(text("SELECT set_config('bastion.allow_audit_mutation', 'on', true)"))
    await session.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": records[-1].id})
    await session.commit()

    verification = await verify_audit_chain(session)
    assert verification.ok is True
    assert verification.head_hash != witness.head_hash
    comparison = await witness_matches(verification, scope=scope, settings=config)
    assert comparison.ok is False
    assert comparison.reason is not None


@pytest.mark.witness_integration
@requires_witness
async def test_unreachable_store_is_not_a_pass() -> None:
    config = witness_settings().model_copy(update={"audit_witness_endpoint": "http://127.0.0.1:1"})
    with pytest.raises(AuditWitnessUnavailable):
        await latest_witness(settings=config)


@pytest.mark.integration
@pytest.mark.witness_integration
@requires_database
@requires_witness
async def test_stored_witness_with_a_broken_signature_is_rejected(
    session: AsyncSession,
) -> None:
    await append_audit_event(
        session,
        actor_id="alice",
        tenant_id="acme",
        event_type=AuditEventType.INPUT_RECEIVED,
        payload={"n": 1},
    )
    await session.commit()
    config = witness_settings()
    scope = scope_name()
    witness = await publish_witness(await verify_audit_chain(session), scope=scope, settings=config)
    client = app_client()
    key = object_key(witness)
    body = json.loads(client.get_object(Bucket=config.audit_witness_bucket, Key=key)["Body"].read())
    body["head_hash"] = GENESIS_HASH
    client.put_object(
        Bucket=config.audit_witness_bucket,
        Key=key,
        Body=json.dumps(body).encode(),
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=retention_until(datetime.now(UTC), 7),
    )
    with pytest.raises(AuditWitnessIntegrityError):
        await latest_witness(scope=scope, settings=config)


# ---------------------------------------------------------------------------
# Operator CLI
# ---------------------------------------------------------------------------


def run_verify_witness(*, endpoint: str | None = None) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "DATABASE_URL": TEST_DATABASE_URL,
        "AUDIT_WITNESS_ENDPOINT": endpoint or os.environ.get("AUDIT_WITNESS_ENDPOINT", ""),
    }
    return subprocess.run(
        [sys.executable, "scripts/verify_audit_chain.py", "--witness", "--json"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.mark.integration
@pytest.mark.witness_integration
@requires_database
@requires_witness
async def test_cli_exits_zero_when_head_and_witness_agree(session: AsyncSession) -> None:
    await append_audit_event(
        session,
        actor_id="alice",
        tenant_id="acme",
        event_type=AuditEventType.INPUT_RECEIVED,
        payload={"n": 1},
    )
    await session.commit()
    config = witness_settings()
    await publish_witness(await verify_audit_chain(session), settings=config)

    result = run_verify_witness()
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["witness"]["ok"] is True


@pytest.mark.integration
@pytest.mark.witness_integration
@requires_database
@requires_witness
async def test_cli_exits_one_when_the_witness_disagrees(session: AsyncSession) -> None:
    records = []
    for index in range(2):
        records.append(
            await append_audit_event(
                session,
                actor_id="alice",
                tenant_id="acme",
                event_type=AuditEventType.INPUT_RECEIVED,
                payload={"index": index},
            )
        )
    await session.commit()
    config = witness_settings()
    await publish_witness(await verify_audit_chain(session), settings=config)

    await session.execute(text("SELECT set_config('bastion.allow_audit_mutation', 'on', true)"))
    await session.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": records[-1].id})
    await session.commit()

    result = run_verify_witness()
    assert result.returncode == 1, result.stderr
    assert json.loads(result.stdout)["witness"]["ok"] is False


@pytest.mark.integration
@pytest.mark.witness_integration
@requires_database
@requires_witness
async def test_cli_exits_two_when_the_store_is_unreachable(session: AsyncSession) -> None:
    await append_audit_event(
        session,
        actor_id="alice",
        tenant_id="acme",
        event_type=AuditEventType.INPUT_RECEIVED,
        payload={"n": 1},
    )
    await session.commit()
    await publish_witness(await verify_audit_chain(session), settings=witness_settings())

    result = run_verify_witness(endpoint="http://127.0.0.1:1")
    assert result.returncode == 2, result.stderr
