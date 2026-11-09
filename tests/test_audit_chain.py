"""Cryptographic audit-chain tests (HANDOVER_SPEC §3.5).

Pure hashing behaviour runs everywhere; ledger integration tests need PostgreSQL
and are marked ``integration``.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from db.audit import append_audit_event, verify_audit_chain
from db.models import (
    GENESIS_HASH,
    AuditEventType,
    AuditLog,
    canonical_timestamp,
    compute_record_hash,
    hash_payload,
)
from tests.conftest import requires_database

# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------


def test_hash_payload_is_order_independent() -> None:
    assert hash_payload({"a": 1, "b": [2, 3]}) == hash_payload({"b": [2, 3], "a": 1})
    assert len(hash_payload({"a": 1})) == 64


def test_hash_payload_distinguishes_content() -> None:
    assert hash_payload({"a": 1}) != hash_payload({"a": 2})
    assert hash_payload("hello") == hashlib.sha256(b"hello").hexdigest()


def test_canonical_timestamp_normalises_to_utc_microseconds() -> None:
    naive = datetime(2026, 11, 9, 12, 0, 0, 123456)
    offset = datetime(2026, 11, 9, 14, 0, 0, 123456, tzinfo=timezone(timedelta(hours=2)))
    assert canonical_timestamp(naive) == "2026-11-09T12:00:00.123456+00:00"
    assert canonical_timestamp(offset) == canonical_timestamp(naive)


def test_record_hash_is_deterministic_and_links_previous() -> None:
    timestamp = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)
    kwargs = {
        "record_id": 1,
        "timestamp": timestamp,
        "actor_id": "alice",
        "event_type": AuditEventType.INPUT_RECEIVED.value,
        "payload_hash": "a" * 64,
        "previous_hash": GENESIS_HASH,
    }
    baseline = compute_record_hash(**kwargs)
    assert baseline == compute_record_hash(**kwargs)
    assert len(baseline) == 64
    assert baseline != compute_record_hash(**{**kwargs, "previous_hash": "b" * 64})
    assert baseline != compute_record_hash(**{**kwargs, "actor_id": "bob"})


def test_record_hash_rejects_malformed_digests() -> None:
    with pytest.raises(ValueError, match="payload_hash"):
        compute_record_hash(
            record_id=1,
            timestamp=datetime.now(UTC),
            actor_id="alice",
            event_type="INPUT_RECEIVED",
            payload_hash="too-short",
            previous_hash=GENESIS_HASH,
        )


# ---------------------------------------------------------------------------
# Ledger integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
@requires_database
async def test_append_links_records_into_a_verifiable_chain(
    session: AsyncSession,
) -> None:
    first = await append_audit_event(
        session,
        actor_id="alice",
        event_type=AuditEventType.INPUT_RECEIVED,
        session_id="sess-1",
        payload={"prompt": "hello"},
        metadata_json={"route": "cloud-primary"},
    )
    second = await append_audit_event(
        session,
        actor_id="alice",
        event_type=AuditEventType.DLP_REDACTION,
        session_id="sess-1",
        payload={"entities": 2},
    )
    third = await append_audit_event(
        session,
        actor_id="gateway",
        event_type=AuditEventType.EGRESS_FILTERED,
        session_id="sess-1",
        payload={"canary_found": False},
    )

    assert first.previous_hash == GENESIS_HASH
    assert second.previous_hash == first.record_hash
    assert third.previous_hash == second.record_hash
    assert first.id < second.id < third.id
    assert all(record.record_hash == record.compute_hash() for record in (first, second, third))

    verification = await verify_audit_chain(session)
    assert verification.ok is True
    assert verification.checked == 3


@pytest.mark.integration
@requires_database
async def test_tampering_with_payload_hash_breaks_verification(
    session: AsyncSession,
) -> None:
    await append_audit_event(
        session, actor_id="alice", event_type=AuditEventType.INPUT_RECEIVED, payload={"n": 1}
    )
    target = await append_audit_event(
        session, actor_id="alice", event_type=AuditEventType.DLP_REDACTION, payload={"n": 2}
    )
    await append_audit_event(
        session, actor_id="alice", event_type=AuditEventType.EGRESS_FILTERED, payload={"n": 3}
    )
    await session.commit()

    # Rewrite history out-of-band, exactly as a compromised operator would.
    # The append-only trigger only lets this through with an explicit opt-in.
    await session.execute(text("SELECT set_config('bastion.allow_audit_mutation', 'on', true)"))
    await session.execute(
        text("UPDATE audit_logs SET payload_hash = :hash WHERE id = :id"),
        {"hash": "f" * 64, "id": target.id},
    )
    await session.commit()
    session.expire_all()

    verification = await verify_audit_chain(session)
    assert verification.ok is False
    assert verification.first_bad_id == target.id
    assert verification.reason == "record_hash does not match record contents"


@pytest.mark.integration
@requires_database
async def test_deleting_a_record_breaks_the_chain(session: AsyncSession) -> None:
    await append_audit_event(
        session, actor_id="alice", event_type=AuditEventType.INPUT_RECEIVED, payload={"n": 1}
    )
    middle = await append_audit_event(
        session, actor_id="alice", event_type=AuditEventType.DLP_REDACTION, payload={"n": 2}
    )
    tail = await append_audit_event(
        session, actor_id="alice", event_type=AuditEventType.EGRESS_FILTERED, payload={"n": 3}
    )
    await session.commit()

    await session.execute(text("SELECT set_config('bastion.allow_audit_mutation', 'on', true)"))
    await session.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": middle.id})
    await session.commit()
    session.expire_all()

    verification = await verify_audit_chain(session)
    assert verification.ok is False
    assert verification.first_bad_id == tail.id
    assert verification.reason == "previous_hash does not link to the preceding record"


@pytest.mark.integration
@requires_database
async def test_database_rejects_update_and_delete(session: AsyncSession) -> None:
    """ADR-005: append-only is enforced by the database, not by convention."""
    record = await append_audit_event(
        session, actor_id="alice", event_type=AuditEventType.INPUT_RECEIVED, payload={"n": 1}
    )
    record_id = record.id
    await session.commit()

    with pytest.raises(DBAPIError, match="append-only"):
        await session.execute(
            text("UPDATE audit_logs SET actor_id = 'mallory' WHERE id = :id"),
            {"id": record_id},
        )
    await session.rollback()

    with pytest.raises(DBAPIError, match="append-only"):
        await session.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": record_id})
    await session.rollback()

    # The record is still intact after both attempts.
    actor = (
        await session.execute(select(AuditLog.actor_id).where(AuditLog.id == record_id))
    ).scalar_one()
    assert actor == "alice"


@pytest.mark.integration
@requires_database
async def test_windowed_verification_checks_only_the_tail(session: AsyncSession) -> None:
    for index in range(5):
        await append_audit_event(
            session,
            actor_id="alice",
            event_type=AuditEventType.INPUT_RECEIVED,
            payload={"n": index},
        )
    await session.commit()

    verification = await verify_audit_chain(session, limit=2)
    assert verification.ok is True
    assert verification.checked == 2


@pytest.mark.integration
@requires_database
async def test_concurrent_appends_never_fork_the_chain(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async def append(index: int) -> None:
        async with session_factory() as db_session:
            await append_audit_event(
                db_session,
                actor_id=f"actor-{index}",
                event_type=AuditEventType.TOOL_REQUESTED,
                session_id="sess-concurrent",
                payload={"index": index},
            )
            await db_session.commit()

    await asyncio.gather(*(append(index) for index in range(8)))

    async with session_factory() as db_session:
        records = list((await db_session.execute(select(AuditLog).order_by(AuditLog.id))).scalars())
        assert len(records) == 8
        verification = await verify_audit_chain(db_session)
        assert verification.ok is True, verification.reason
        assert verification.checked == 8
