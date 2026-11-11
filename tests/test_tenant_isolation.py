"""Cross-tenant access must fail for vault tokens, tickets and audit rows (ADR-015)."""

# pylint: disable=protected-access  # tests assert key and AAD boundaries

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, cast

import pytest
import pytest_asyncio
from fakeredis import FakeAsyncRedis
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from agent.dlp.vault import TokenVault, VaultDecryptionError
from agent.egress.sanitizer import EgressSanitizer
from db.audit import append_audit_event
from db.models import AuditEventType
from gateway.approvals import ApprovalDecisionError, decide_ticket, list_pending
from gateway.audit_service import AuditFilters, list_records
from gateway.queue import enqueue_tool_resume
from settings import reset_settings_cache
from tests.conftest import requires_database
from tests.test_approvals import build_ticket

KEY = b"t" * 32
PREFIX = "BASTION-CANARY-"
ACME = "acme"
GLOBEX = "globex"


@pytest_asyncio.fixture
async def tenancy_env() -> AsyncIterator[tuple[EgressSanitizer, TokenVault, FakeAsyncRedis]]:
    redis = FakeAsyncRedis(decode_responses=True)
    vault = TokenVault(redis, key=KEY, ttl_seconds=60)
    sanitizer = EgressSanitizer(
        vault,
        cast(Redis, redis),
        canary_prefix=PREFIX,
        canary_ttl_seconds=60,
        trip_ttl_seconds=60,
    )
    try:
        yield sanitizer, vault, redis
    finally:
        await redis.aclose()


async def test_vault_token_cannot_be_read_by_another_tenant(
    tenancy_env: tuple[EgressSanitizer, TokenVault, FakeAsyncRedis],
) -> None:
    _sanitizer, vault, _redis = tenancy_env
    token = await vault.get_or_create(ACME, "same-session", "EMAIL_ADDRESS", "alice@example.com")

    assert await vault.get(ACME, "same-session", token) == "alice@example.com"
    assert await vault.get(GLOBEX, "same-session", token) is None
    assert await vault.restore(GLOBEX, "same-session", f"Hello {token}") == f"Hello {token}"
    assert vault._keys(ACME, "same-session")[0].startswith("vault:acme:")
    assert "vault:globex:" in vault._keys(GLOBEX, "same-session")[0]


async def test_ciphertext_copied_to_another_tenant_fails_authentication(
    tenancy_env: tuple[EgressSanitizer, TokenVault, FakeAsyncRedis],
) -> None:
    _sanitizer, vault, redis = tenancy_env
    token = await vault.get_or_create(ACME, "same-session", "EMAIL_ADDRESS", "alice@example.com")
    acme_key = vault._keys(ACME, "same-session")[0]
    globex_key = vault._keys(GLOBEX, "same-session")[0]
    ciphertext = await redis.hget(acme_key, token)
    assert ciphertext

    # Same tenant session and token name, different tenant: the AAD must reject it.
    await redis.hset(globex_key, token, ciphertext)
    with pytest.raises(VaultDecryptionError):
        await vault.get(GLOBEX, "same-session", token)
    assert await vault.get(ACME, "same-session", token) == "alice@example.com"


async def test_canary_and_quarantine_are_tenant_scoped(
    tenancy_env: tuple[EgressSanitizer, TokenVault, FakeAsyncRedis],
) -> None:
    sanitizer, _vault, _redis = tenancy_env
    acme_canary = await sanitizer.canary_for(ACME, "same-session")
    globex_canary = await sanitizer.canary_for(GLOBEX, "same-session")
    assert acme_canary != globex_canary

    await sanitizer.trip(ACME, "same-session", "canary_leak")
    assert await sanitizer.is_tripped(ACME, "same-session") is True
    assert await sanitizer.is_tripped(GLOBEX, "same-session") is False
    assert sanitizer._key(ACME, "canary", "same-session").startswith("egress:acme:canary:")
    assert sanitizer._key(GLOBEX, "trip", "same-session").startswith("egress:globex:trip:")


async def test_approval_job_id_is_tenant_qualified(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakePool:
        async def enqueue_job(self, _name: str, **kwargs: Any) -> object:
            captured.update(kwargs)
            return object()

    async def fake_pool() -> FakePool:
        return FakePool()

    monkeypatch.setenv("TOOL_RESUME_AUTO_ENQUEUE", "true")
    monkeypatch.setattr("gateway.queue.get_arq_pool", fake_pool)
    reset_settings_cache()
    try:
        assert await enqueue_tool_resume(ACME, "ticket-1") is True
    finally:
        reset_settings_cache()

    assert captured["_job_id"] == "resume:acme:ticket-1"


@pytest.mark.integration
@requires_database
async def test_ticket_from_another_tenant_is_invisible_and_undecidable(
    session: AsyncSession,
) -> None:
    ticket, _token = build_ticket(initiator_id="alice", tenant_id=ACME)
    session.add(ticket)
    await session.flush()
    assert ticket.tenant_id == ACME

    globex_queue = await list_pending(
        session,
        viewer_id="bob",
        viewer_roles=frozenset({"operator"}),
        tenant_id=GLOBEX,
    )
    assert globex_queue == []

    with pytest.raises(ApprovalDecisionError) as refusal:
        await decide_ticket(
            session,
            ticket_id=ticket.ticket_id,
            actor_id="bob",
            actor_roles=frozenset({"operator"}),
            tenant_id=GLOBEX,
            action="approve",
        )
    assert refusal.value.code == "not_found"
    assert refusal.value.status_code == 404


@pytest.mark.integration
@requires_database
async def test_audit_queries_are_tenant_scoped(session: AsyncSession) -> None:
    await append_audit_event(
        session,
        actor_id="alice",
        tenant_id=ACME,
        event_type=AuditEventType.INPUT_RECEIVED,
        payload={"turn": 1},
    )
    await session.flush()

    acme_page = await list_records(session, AuditFilters(), tenant_id=ACME)
    globex_page = await list_records(session, AuditFilters(), tenant_id=GLOBEX)
    assert acme_page.records
    assert acme_page.records[0].tenant_id == ACME
    assert globex_page.records == []
