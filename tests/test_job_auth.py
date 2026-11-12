"""Signed job envelopes: forged identity never reaches the guard (ADR-018).

The unit half proves the envelope primitives; the database half drives
``execute_tool_job`` the way a Redis writer would and asserts that a forged
payload leaves no audit row, no ticket and no execution behind.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from fakeredis import FakeAsyncRedis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from agent.job_auth import (
    DEMO_JOB,
    RESUME_JOB,
    TOOL_JOB,
    JobSignatureError,
    consume_nonce,
    demo_job_fields,
    resume_job_fields,
    sign_job,
    tool_job_fields,
    verify_and_consume,
    verify_job,
)
from db.models import AuditEventType, AuditLog, PendingApproval, utcnow
from gateway.queue import enqueue_demo_run, enqueue_tool_resume
from settings import get_settings, reset_settings_cache
from tests.conftest import requires_database

SETTINGS = get_settings()
SECRET = SETTINGS.job_signing_secret.get_secret_value()
TTL = SETTINGS.job_signature_ttl_seconds

FIELDS = tool_job_fields(
    tool_name="execute_file_write",
    actor_id="alice",
    tenant_id="acme",
    session_id="sess-job-auth",
    roles=["operator"],
    arguments={"path": "reports/q1.txt", "content": "q1 revenue"},
)


def mint(kind: str = TOOL_JOB, fields: dict[str, Any] | None = None, **overrides: Any) -> dict:
    payload = FIELDS if fields is None else fields
    envelope = sign_job(kind, payload, secret=SECRET, ttl_seconds=TTL, **overrides)
    return {**payload, **envelope}


# ---------------------------------------------------------------------------
# Envelope primitives
# ---------------------------------------------------------------------------


def test_a_minted_envelope_verifies() -> None:
    envelope = mint()
    verify_job(
        TOOL_JOB,
        FIELDS,
        nonce=envelope["job_nonce"],
        expires_at=envelope["job_expires_at"],
        signature=envelope["job_signature"],
        secret=SECRET,
    )


def test_a_tampered_identity_breaks_the_signature() -> None:
    envelope = mint()
    forged = {**FIELDS, "actor_id": "mallory"}
    with pytest.raises(JobSignatureError) as caught:
        verify_job(
            TOOL_JOB,
            forged,
            nonce=envelope["job_nonce"],
            expires_at=envelope["job_expires_at"],
            signature=envelope["job_signature"],
            secret=SECRET,
        )
    assert caught.value.reason == "bad_signature"


def test_a_different_key_cannot_validate_the_envelope() -> None:
    envelope = mint()
    with pytest.raises(JobSignatureError) as caught:
        verify_job(
            TOOL_JOB,
            FIELDS,
            nonce=envelope["job_nonce"],
            expires_at=envelope["job_expires_at"],
            signature=envelope["job_signature"],
            secret="not-the-signing-key",
        )
    assert caught.value.reason == "bad_signature"


def test_a_missing_envelope_is_refused() -> None:
    with pytest.raises(JobSignatureError) as caught:
        verify_job(TOOL_JOB, FIELDS, nonce="", expires_at="", signature="", secret=SECRET)
    assert caught.value.reason == "unsigned_job"


def test_an_expired_envelope_is_refused() -> None:
    issued = utcnow() - timedelta(seconds=TTL + 60)
    envelope = mint(now=issued)
    with pytest.raises(JobSignatureError) as caught:
        verify_job(
            TOOL_JOB,
            FIELDS,
            nonce=envelope["job_nonce"],
            expires_at=envelope["job_expires_at"],
            signature=envelope["job_signature"],
            secret=SECRET,
        )
    assert caught.value.reason == "expired_job"


async def test_a_replayed_nonce_is_refused() -> None:
    redis = FakeAsyncRedis(decode_responses=True)
    try:
        assert await consume_nonce(redis, "nonce-1", ttl_seconds=60) is True
        assert await consume_nonce(redis, "nonce-1", ttl_seconds=60) is False
    finally:
        await redis.aclose()


async def test_verify_and_consume_burns_the_nonce_once() -> None:
    redis = FakeAsyncRedis(decode_responses=True)
    envelope = mint()
    try:
        await verify_and_consume(
            redis,
            TOOL_JOB,
            FIELDS,
            nonce=envelope["job_nonce"],
            expires_at=envelope["job_expires_at"],
            signature=envelope["job_signature"],
            secret=SECRET,
            ttl_seconds=TTL,
        )
        with pytest.raises(JobSignatureError) as caught:
            await verify_and_consume(
                redis,
                TOOL_JOB,
                FIELDS,
                nonce=envelope["job_nonce"],
                expires_at=envelope["job_expires_at"],
                signature=envelope["job_signature"],
                secret=SECRET,
                ttl_seconds=TTL,
            )
    finally:
        await redis.aclose()
    assert caught.value.reason == "replayed_job"


# ---------------------------------------------------------------------------
# The worker refuses a forged payload before it has any effect
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_redis(monkeypatch) -> FakeAsyncRedis:
    """Point the worker's nonce store at an in-memory Redis."""
    client = FakeAsyncRedis(decode_responses=True)
    monkeypatch.setattr("agent.runtime.get_redis", lambda *_args, **_kwargs: client)
    return client


REDIS_TEST_URL = os.getenv("REDIS_TEST_URL", "")


@pytest.mark.redis_integration
@pytest.mark.skipif(not REDIS_TEST_URL, reason="REDIS_TEST_URL is not set")
async def test_a_real_redis_refuses_a_second_claim() -> None:
    """The single-use property against a live server, not fakeredis."""
    from redis.asyncio import Redis

    client = Redis.from_url(REDIS_TEST_URL, decode_responses=True)
    nonce = f"test-{uuid.uuid4().hex}"
    try:
        assert await consume_nonce(client, nonce, ttl_seconds=30) is True
        assert await consume_nonce(client, nonce, ttl_seconds=30) is False
        assert await client.ttl(f"job:nonce:{nonce}") > 0
    finally:
        await client.delete(f"job:nonce:{nonce}")
        await client.aclose()


@pytest.fixture
def worker_db(db_engine, monkeypatch) -> Iterator[Any]:
    from db import session as db_session

    monkeypatch.setattr(db_session, "_engine", db_engine)
    monkeypatch.setattr(db_session, "_session_factory", None)
    yield db_engine
    monkeypatch.setattr(db_session, "_session_factory", None)


async def _ledger(db_engine: Any) -> tuple[list[AuditLog], list[PendingApproval]]:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        records = list((await session.execute(select(AuditLog).order_by(AuditLog.id))).scalars())
        tickets = list((await session.execute(select(PendingApproval))).scalars())
    return records, tickets


@requires_database
async def test_an_unsigned_job_leaves_no_trace(worker_db, fake_redis) -> None:
    from agent.runtime import execute_tool_job

    result = await execute_tool_job(
        {"job_id": "test-unsigned"},
        tool_name="execute_file_write",
        actor_id="alice",
        tenant_id="acme",
        roles=["operator"],
        session_id="sess-unsigned",
        arguments={"path": "reports/q1.txt"},
    )

    assert result["status"] == "unauthorized_job"
    assert result["error"] == "unsigned_job"
    records, tickets = await _ledger(worker_db)
    assert records == []
    assert tickets == []


@requires_database
async def test_a_forged_initiator_cannot_create_a_ticket(worker_db, fake_redis) -> None:
    from agent.runtime import execute_tool_job

    envelope = mint()
    result = await execute_tool_job(
        {"job_id": "test-forged-actor"},
        **{**FIELDS, **envelope, "actor_id": "mallory"},
    )

    assert result["status"] == "unauthorized_job"
    assert result["error"] == "bad_signature"
    records, tickets = await _ledger(worker_db)
    assert records == []
    assert tickets == []


@requires_database
async def test_a_forged_tenant_cannot_cross_the_boundary(worker_db, fake_redis) -> None:
    from agent.runtime import execute_tool_job

    envelope = mint()
    result = await execute_tool_job(
        {"job_id": "test-forged-tenant"},
        **{**FIELDS, **envelope, "tenant_id": "globex"},
    )

    assert result["status"] == "unauthorized_job"
    records, tickets = await _ledger(worker_db)
    assert records == []
    assert tickets == []


@requires_database
async def test_a_replayed_job_is_refused(worker_db, fake_redis) -> None:
    from agent.runtime import execute_tool_job

    payload = mint()
    first = await execute_tool_job({"job_id": "test-replay"}, **payload)
    second = await execute_tool_job({"job_id": "test-replay"}, **payload)

    assert first["status"] == "approval_pending"
    assert second["status"] == "unauthorized_job"
    assert second["error"] == "replayed_job"
    records, tickets = await _ledger(worker_db)
    assert len(tickets) == 1
    assert [record.event_type for record in records].count(AuditEventType.APPROVAL_REQUESTED) == 1


@requires_database
async def test_a_minted_job_still_executes(worker_db, fake_redis) -> None:
    from agent.runtime import execute_tool_job

    payload = mint(
        fields=tool_job_fields(
            tool_name="read_system_status",
            actor_id="alice",
            tenant_id="acme",
            session_id="sess-minted",
            roles=["operator"],
            arguments={},
        )
    )
    result = await execute_tool_job({"job_id": "test-minted"}, **payload)

    assert result["status"] == "executed"
    records, tickets = await _ledger(worker_db)
    assert not tickets
    assert [record.event_type for record in records] == [
        AuditEventType.TOOL_REQUESTED,
        AuditEventType.TOOL_EXECUTED,
    ]


@requires_database
async def test_a_forged_demo_run_is_refused(worker_db, fake_redis) -> None:
    from agent.runtime import run_demo_scenario_job

    result = await run_demo_scenario_job(
        {"job_id": "test-demo-forgery"},
        run_id="run-1",
        scenario_id="read_only_status",
        actor_id="mallory",
        tenant_id="globex",
        roles=["admin"],
        session_id="demo-run-1",
    )

    assert result["status"] == "unauthorized_job"
    records, tickets = await _ledger(worker_db)
    assert records == []
    assert tickets == []


# ---------------------------------------------------------------------------
# The gateway mints what the worker verifies
# ---------------------------------------------------------------------------


async def test_the_gateway_mints_a_verifiable_demo_job(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    class _Pool:
        async def enqueue_job(self, name: str, **kwargs: Any) -> object:
            captured["name"] = name
            captured.update(kwargs)
            return object()

    async def _pool() -> _Pool:
        return _Pool()

    monkeypatch.setattr("gateway.queue.get_arq_pool", _pool)
    assert await enqueue_demo_run(
        run_id="run-2",
        scenario_id="read_only_status",
        actor_id="alice",
        tenant_id="acme",
        roles=["operator"],
        session_id="demo-run-2",
    )

    fields = demo_job_fields(
        run_id="run-2",
        scenario_id="read_only_status",
        actor_id="alice",
        tenant_id="acme",
        roles=["operator"],
        session_id="demo-run-2",
    )
    redis = FakeAsyncRedis(decode_responses=True)
    try:
        await verify_and_consume(
            redis,
            DEMO_JOB,
            fields,
            nonce=captured["job_nonce"],
            expires_at=captured["job_expires_at"],
            signature=captured["job_signature"],
            secret=SECRET,
            ttl_seconds=TTL,
        )
    finally:
        await redis.aclose()


async def test_the_gateway_mints_a_verifiable_resume_job(monkeypatch) -> None:
    """The approval route and the worker agree on the resume envelope."""
    monkeypatch.setenv("TOOL_RESUME_AUTO_ENQUEUE", "true")
    reset_settings_cache()
    captured: dict[str, Any] = {}

    class _Pool:
        async def enqueue_job(self, name: str, **kwargs: Any) -> object:
            captured["name"] = name
            captured.update(kwargs)
            return object()

    async def _pool() -> _Pool:
        return _Pool()

    monkeypatch.setattr("gateway.queue.get_arq_pool", _pool)
    try:
        assert await enqueue_tool_resume("acme", "ticket-1") is True
    finally:
        reset_settings_cache()

    assert captured["name"] == "resume_tool_job"
    verify_job(
        RESUME_JOB,
        resume_job_fields(ticket_id="ticket-1", tenant_id="acme"),
        nonce=captured["job_nonce"],
        expires_at=captured["job_expires_at"],
        signature=captured["job_signature"],
        secret=SECRET,
    )


async def test_the_signing_key_is_not_the_approval_key() -> None:
    assert SETTINGS.approval_hmac_secret.get_secret_value() != SECRET
