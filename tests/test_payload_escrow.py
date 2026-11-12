"""Payload-escrow tests (ADR-005 decision 7).

The chat path, DLP engine and egress sanitizer run for real; only the OmniRoute
boundary is stubbed, exactly as in ``tests/test_chat.py``. The properties under
test are the ones that make the store safe to switch on: the ledger is unchanged,
the ciphertext is bound to its record, the plaintext never appears in the table
or the logs, reads are admin-only and audited, and expiry is a row delete.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import httpx
import pytest
import pytest_asyncio
from fakeredis import FakeAsyncRedis
from redis.asyncio import Redis
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from agent.dlp.presidio import PresidioDLP, get_analyzer
from agent.dlp.vault import TokenVault
from agent.egress.sanitizer import EgressSanitizer
from agent.routing.classifier import Classification, Sensitivity
from agent.routing.client import ChatCompletion, ChatMessage, RouteDecision
from db.audit import append_audit_event, verify_audit_chain
from db.escrow import (
    EscrowDecryptionError,
    EscrowExpiredError,
    EscrowPayloadMismatchError,
    PayloadEscrowCodec,
    purge_expired_escrow,
    read_payload_escrow,
    record_payload_escrow,
)
from db.models import (
    AuditEventType,
    AuditLog,
    EscrowKind,
    PayloadEscrow,
    hash_payload,
    utcnow,
)
from db.session import get_db_session
from gateway.auth.oidc import Principal
from gateway.auth.rbac import AuthContext, get_auth_context
from gateway.main import create_app
from gateway.routers.chat import get_chat_dlp, get_chat_router, get_chat_sanitizer
from settings import get_settings, reset_settings_cache
from tests.conftest import requires_database

pytestmark = [pytest.mark.integration, requires_database]

KEY = b"a" * 32
PREFIX = "BASTION-CANARY-"
CONVERSATION = "conv-escrow"
FIXED_TIME = datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)

ALICE = Principal(
    subject="alice-sub", tenant_id="acme", username="alice", roles=frozenset({"operator"})
)
ADMIN = Principal(
    subject="breakglass-sub", tenant_id="acme", username="breakglass", roles=frozenset({"admin"})
)
READONLY = Principal(
    subject="dave-sub", tenant_id="acme", username="dave", roles=frozenset({"readonly"})
)
ANALYST = Principal(
    subject="carol-sub", tenant_id="acme", username="carol", roles=frozenset({"analyst"})
)

PUBLIC = Classification(Sensitivity.PUBLIC, 0.99, "stub-classifier", reason="public_content")


@dataclass
class StubRouter:
    """Minimal model-router double; the guardrails are the real ones."""

    async def aroute(self, prompt: str, *, pii_detected: bool = False) -> RouteDecision:
        local = pii_detected
        return RouteDecision(
            alias="local-llama" if local else "cloud-primary",
            classification=PUBLIC,
            local=local,
            override="pii_detected" if pii_detected else None,
        )

    async def complete(
        self,
        messages: list[ChatMessage],
        *,
        decision: RouteDecision | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> ChatCompletion:
        alias = decision.alias if decision is not None else "cloud-primary"
        return ChatCompletion(content="A normal answer.", model=alias)


@dataclass
class Harness:
    client: httpx.AsyncClient
    factory: async_sessionmaker[AsyncSession]
    state: dict[str, Any]
    redis: FakeAsyncRedis


def _enable_escrow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAYLOAD_ESCROW_ENABLED", "true")
    monkeypatch.setenv("PAYLOAD_ESCROW_TTL_SECONDS", "60")
    reset_settings_cache()


@pytest.fixture
def escrow_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the flag off so a developer's ``.env`` cannot change the assertion."""
    monkeypatch.setenv("PAYLOAD_ESCROW_ENABLED", "false")
    reset_settings_cache()


@pytest.fixture
def escrow_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable escrow with a one-minute window for the duration of a test."""
    _enable_escrow(monkeypatch)


@asynccontextmanager
async def _chat_app(db_engine: AsyncEngine) -> AsyncIterator[Harness]:
    redis = FakeAsyncRedis(decode_responses=True)
    vault = TokenVault(redis, key=KEY, ttl_seconds=60)
    dlp = PresidioDLP(vault, analyzer=get_analyzer())
    sanitizer = EgressSanitizer(
        vault,
        cast(Redis, redis),
        canary_prefix=PREFIX,
        canary_ttl_seconds=60,
        trip_ttl_seconds=60,
    )
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    app = create_app()

    async def override_db() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
            except BaseException:
                await session.rollback()
                raise
            await session.commit()

    state: dict[str, Any] = {"context": AuthContext(principal=ALICE, method="bearer")}

    def current_context() -> AuthContext:
        return state["context"]

    def model_router() -> StubRouter:
        return StubRouter()

    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_auth_context] = current_context
    app.dependency_overrides[get_chat_router] = model_router
    app.dependency_overrides[get_chat_dlp] = lambda: dlp
    app.dependency_overrides[get_chat_sanitizer] = lambda: sanitizer

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=False
    ) as client:
        try:
            yield Harness(client=client, factory=factory, state=state, redis=redis)
        finally:
            await redis.aclose()


@pytest_asyncio.fixture
async def chat_api(db_engine: AsyncEngine, escrow_off: None) -> AsyncIterator[Harness]:
    # pylint: disable-next=contextmanager-generator-missing-cleanup
    async with _chat_app(db_engine) as harness:
        yield harness


@pytest_asyncio.fixture
async def escrow_api(db_engine: AsyncEngine, escrow_on: None) -> AsyncIterator[Harness]:
    # pylint: disable-next=contextmanager-generator-missing-cleanup
    async with _chat_app(db_engine) as harness:
        yield harness


def body(content: str) -> dict[str, Any]:
    return {
        "conversation_id": CONVERSATION,
        "messages": [{"role": "user", "content": content}],
    }


async def _records(harness: Harness) -> list[AuditLog]:
    async with harness.factory() as session:
        result = await session.execute(
            select(AuditLog).where(AuditLog.session_id == CONVERSATION).order_by(AuditLog.id)
        )
        return list(result.scalars())


async def _escrow_rows(harness: Harness) -> list[PayloadEscrow]:
    async with harness.factory() as session:
        result = await session.execute(select(PayloadEscrow))
        return list(result.scalars())


async def test_flag_off_writes_no_escrow_rows(chat_api: Harness) -> None:
    response = await chat_api.client.post(
        "/v1/chat", json=body("Please email alice@example.com about the contract.")
    )

    assert response.status_code == 200, response.text
    assert await _escrow_rows(chat_api) == []
    records = await _records(chat_api)
    assert records[0].event_type is AuditEventType.INPUT_RECEIVED


async def test_flag_on_writes_exactly_one_escrow_row_per_escrowed_event(
    escrow_api: Harness,
) -> None:
    response = await escrow_api.client.post(
        "/v1/chat", json=body("Please email alice@example.com about the contract.")
    )

    assert response.status_code == 200, response.text
    rows = await _escrow_rows(escrow_api)
    # One turn writes five lifecycle rows and escrows two of them: the raw input
    # and the sanitized answer, each keyed to its own ledger record.
    assert len(rows) == 2
    by_kind = {row.kind: row for row in rows}
    records = await _records(escrow_api)
    input_record = next(
        record for record in records if record.event_type is AuditEventType.INPUT_RECEIVED
    )
    response_record = next(
        record for record in records if record.event_type is AuditEventType.RESPONSE_SENT
    )
    assert by_kind[EscrowKind.INPUT_RAW].audit_log_id == input_record.id
    assert by_kind[EscrowKind.INPUT_RAW].payload_hash == input_record.payload_hash
    assert by_kind[EscrowKind.EGRESS_DELIVERED].audit_log_id == response_record.id
    assert by_kind[EscrowKind.EGRESS_DELIVERED].payload_hash == response_record.payload_hash

    verified = await escrow_api.client.post("/api/audit/verify")
    assert verified.status_code == 200, verified.text
    assert verified.json()["ok"] is True


async def test_ciphertext_is_aes_gcm_with_a_per_record_nonce(
    escrow_api: Harness,
) -> None:
    for _ in range(2):
        response = await escrow_api.client.post("/v1/chat", json=body("A routine question."))
        assert response.status_code == 200, response.text

    rows = [row for row in await _escrow_rows(escrow_api) if row.kind is EscrowKind.INPUT_RAW]
    assert len(rows) == 2
    for row in rows:
        assert len(row.nonce) == 12
        assert row.ciphertext
        assert b"A routine question." not in row.ciphertext
    assert rows[0].nonce != rows[1].nonce

    # The AEAD associated data binds the ciphertext to its own audit id: moving
    # a valid row to another record must fail authentication.
    codec = PayloadEscrowCodec(get_settings().payload_escrow_key_bytes)
    with pytest.raises(EscrowDecryptionError):
        codec.decrypt(
            audit_log_id=rows[0].audit_log_id + 1,
            payload_hash=rows[0].payload_hash,
            tenant_id=rows[0].tenant_id,
            kind=rows[0].kind,
            nonce=rows[0].nonce,
            ciphertext=rows[0].ciphertext,
        )


async def test_escrow_table_and_logs_contain_no_plaintext(
    escrow_api: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    marker = "ESCROW-PLAINTEXT-MARKER-91b2"
    caplog.set_level(logging.DEBUG)

    response = await escrow_api.client.post(
        "/v1/chat", json=body(f"Reference {marker} in the report.")
    )

    assert response.status_code == 200, response.text
    rows = await _escrow_rows(escrow_api)
    assert len(rows) == 2
    for row in rows:
        dumped = " ".join(str(value) for value in vars(row).values())
        assert marker not in dumped
        assert marker.encode() not in row.ciphertext
    assert marker not in caplog.text


async def test_decrypt_round_trips_to_the_ledger_hash(escrow_api: Harness) -> None:
    payload = [{"role": "user", "content": "Please email alice@example.com about the contract."}]
    await escrow_api.client.post("/v1/chat", json=body(payload[0]["content"]))

    async with escrow_api.factory() as session:
        input_record = (
            await session.execute(
                select(AuditLog).where(AuditLog.event_type == AuditEventType.INPUT_RECEIVED)
            )
        ).scalar_one()
        escrow = await read_payload_escrow(
            session, audit_log_id=int(input_record.id), tenant_id="acme"
        )

    assert escrow.payload == payload
    assert hash_payload(escrow.payload) == input_record.payload_hash


async def test_chain_stays_green_and_hashes_are_identical_flag_on_and_off(
    db_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A fixed clock makes the id/timestamp/hash inputs comparable across runs.
    monkeypatch.setattr("db.audit.utcnow", lambda: FIXED_TIME)
    monkeypatch.setenv("PAYLOAD_ESCROW_ENABLED", "false")
    reset_settings_cache()
    payload = [{"role": "user", "content": "Please email alice@example.com about the contract."}]
    # The explicit sequence is not owned by the table, so `RESTART IDENTITY`
    # does not reset it; do it here to make both runs start at id 1.
    async with db_engine.begin() as connection:
        await connection.execute(text("ALTER SEQUENCE audit_logs_id_seq RESTART WITH 1"))

    async with _chat_app(db_engine) as off_harness:
        response = await off_harness.client.post("/v1/chat", json=body(payload[0]["content"]))
        assert response.status_code == 200, response.text
        off_record = next(
            record
            for record in await _records(off_harness)
            if record.event_type is AuditEventType.INPUT_RECEIVED
        )
        assert not await _escrow_rows(off_harness)
        async with off_harness.factory() as session:
            assert (await verify_audit_chain(session)).ok

    async with db_engine.begin() as connection:
        await connection.execute(
            text("TRUNCATE TABLE audit_logs, payload_escrow RESTART IDENTITY CASCADE")
        )
        await connection.execute(text("ALTER SEQUENCE audit_logs_id_seq RESTART WITH 1"))

    _enable_escrow(monkeypatch)
    async with _chat_app(db_engine) as on_harness:
        response = await on_harness.client.post("/v1/chat", json=body(payload[0]["content"]))
        assert response.status_code == 200, response.text
        on_record = next(
            record
            for record in await _records(on_harness)
            if record.event_type is AuditEventType.INPUT_RECEIVED
        )
        assert len(await _escrow_rows(on_harness)) == 2
        async with on_harness.factory() as session:
            assert (await verify_audit_chain(session)).ok

    assert on_record.payload_hash == off_record.payload_hash
    assert on_record.record_hash == off_record.record_hash


async def test_decrypt_is_admin_only_and_audited(escrow_api: Harness) -> None:
    await escrow_api.client.post("/v1/chat", json=body("A routine question."))
    async with escrow_api.factory() as session:
        input_record = (
            await session.execute(
                select(AuditLog).where(AuditLog.event_type == AuditEventType.INPUT_RECEIVED)
            )
        ).scalar_one()
        record_id = int(input_record.id)

    for principal in (READONLY, ANALYST):
        escrow_api.state["context"] = AuthContext(principal=principal, method="bearer")
        response = await escrow_api.client.post(f"/api/audit/{record_id}/escrow")
        assert response.status_code == 403, response.text

    async with escrow_api.factory() as session:
        denied = (
            await session.execute(
                select(AuditLog).where(AuditLog.event_type == AuditEventType.ESCROW_ACCESSED)
            )
        ).scalars()
        assert not list(denied)

    escrow_api.state["context"] = AuthContext(principal=ADMIN, method="bearer")
    response = await escrow_api.client.post(f"/api/audit/{record_id}/escrow")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["audit_log_id"] == record_id
    assert data["kind"] == "input_raw"
    assert data["payload"] == [{"role": "user", "content": "A routine question."}]
    assert data["payload_hash"] == input_record.payload_hash

    async with escrow_api.factory() as session:
        accessed = (
            await session.execute(
                select(AuditLog).where(AuditLog.event_type == AuditEventType.ESCROW_ACCESSED)
            )
        ).scalars()
        rows = list(accessed)
        assert len(rows) == 1
        assert rows[0].actor_id == ADMIN.subject
        assert rows[0].metadata_json == {
            "audit_log_id": record_id,
            "kind": "input_raw",
            "outcome": "decrypted",
        }


async def test_expired_rows_are_refused_and_purged_without_touching_the_chain(
    escrow_api: Harness,
) -> None:
    await escrow_api.client.post("/v1/chat", json=body("A routine question."))
    async with escrow_api.factory() as session:
        input_record = (
            await session.execute(
                select(AuditLog).where(AuditLog.event_type == AuditEventType.INPUT_RECEIVED)
            )
        ).scalar_one()
        record_id = int(input_record.id)
        now = utcnow()
        await session.execute(
            update(PayloadEscrow).values(
                created_at=now - timedelta(hours=2),
                expires_at=now - timedelta(hours=1),
            )
        )
        await session.commit()

    async with escrow_api.factory() as session:
        with pytest.raises(EscrowExpiredError):
            await read_payload_escrow(session, audit_log_id=record_id, tenant_id="acme")

    async with escrow_api.factory() as session:
        assert await purge_expired_escrow(session) == 2
        await session.commit()

    async with escrow_api.factory() as session:
        assert not list((await session.execute(select(PayloadEscrow))).scalars())
        assert (
            await session.execute(select(AuditLog).where(AuditLog.id == record_id))
        ).scalar_one() is not None
        assert (await verify_audit_chain(session)).ok


async def test_purge_job_uses_the_shared_sweep(
    escrow_api: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ARQ cron job purges through the same statement the script uses."""
    from agent import runtime

    await escrow_api.client.post("/v1/chat", json=body("A routine question."))
    async with escrow_api.factory() as session:
        now = utcnow()
        await session.execute(
            update(PayloadEscrow).values(
                created_at=now - timedelta(hours=2),
                expires_at=now - timedelta(hours=1),
            )
        )
        await session.commit()

    @asynccontextmanager
    async def scope() -> AsyncIterator[AsyncSession]:
        async with escrow_api.factory() as session:
            try:
                yield session
            except BaseException:
                await session.rollback()
                raise
            await session.commit()

    monkeypatch.setattr(runtime, "session_scope", scope)
    assert runtime.purge_expired_payload_escrow_job in runtime.WorkerSettings.functions
    assert await runtime.purge_expired_payload_escrow_job({}) == {"purged": 2}
    assert not await _escrow_rows(escrow_api)


async def test_writer_rejects_a_payload_that_does_not_match_the_ledger_hash(
    escrow_api: Harness,
) -> None:
    async with escrow_api.factory() as session:
        record = await append_audit_event(
            session,
            actor_id="alice-sub",
            tenant_id="acme",
            event_type=AuditEventType.INPUT_RECEIVED,
            payload={"role": "user", "content": "original"},
        )
        with pytest.raises(EscrowPayloadMismatchError, match="payload_hash"):
            await record_payload_escrow(session, record, {"role": "user", "content": "swapped"})
