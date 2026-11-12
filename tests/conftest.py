"""Shared pytest fixtures.

Database-backed tests require a disposable PostgreSQL 16 instance:

    docker run --rm -d --name bastion-test-db -p 55433:5432 \\
        -e POSTGRES_USER=bastion -e POSTGRES_PASSWORD=bastion \\
        -e POSTGRES_DB=bastion_test postgres:16-alpine

    TEST_DATABASE_URL=postgresql+asyncpg://bastion:bastion@localhost:55433/bastion_test \\
        uv run pytest -m integration

The suite refuses to touch a database whose name does not contain ``test``.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from db.models import AUDIT_EVENT_VOCABULARY_DDL, ESCROW_KIND_DDL, TENANT_SCOPE_DDL, Base

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL", "")

requires_database = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is not set",
)


def _assert_safe_target() -> str:
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL is not set")
    database_name = TEST_DATABASE_URL.rsplit("/", 1)[-1].split("?", 1)[0]
    if "test" not in database_name:
        pytest.exit(
            "refusing to run destructive tests: database name "
            f"{database_name!r} does not contain 'test'",
            returncode=2,
        )
    return TEST_DATABASE_URL


@pytest_asyncio.fixture
async def db_engine() -> AsyncIterator[AsyncEngine]:
    """Fresh engine per test, with an empty schema."""
    url = _assert_safe_target()
    engine = create_async_engine(url, poolclass=NullPool)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        # Upgrade a reused test database that predates ADR-015.
        for statement in TENANT_SCOPE_DDL:
            await connection.execute(text(statement))
        # ...or predates ESCROW_ACCESSED in the audit event vocabulary.
        for statement in AUDIT_EVENT_VOCABULARY_DDL:
            await connection.execute(text(statement))
        # ...or predates the egress_delivered escrow kind.
        for statement in ESCROW_KIND_DDL:
            await connection.execute(text(statement))
        await connection.execute(
            text(
                "TRUNCATE TABLE payload_escrow, audit_logs, pending_approvals "
                "RESTART IDENTITY CASCADE"
            )
        )
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def session(db_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Uncommitted session, rolled back when the test finishes."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db_session:
        try:
            yield db_session
        finally:
            await db_session.rollback()


@pytest_asyncio.fixture
async def session_factory(db_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Session factory for tests that need independent concurrent transactions."""
    return async_sessionmaker(db_engine, expire_on_commit=False)


@pytest.fixture(autouse=True)
def _disable_payload_escrow(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep a developer's ``.env`` from enabling the pre-production escrow.

    DeepEval's pytest plugin loads ``.env`` into ``os.environ`` at session
    start, so a local stack configured for debugging would otherwise change the
    default-path tests. The escrow suites opt in explicitly.
    """
    from settings import reset_settings_cache

    monkeypatch.setenv("PAYLOAD_ESCROW_ENABLED", "false")
    monkeypatch.setenv("RESPONSE_STORE_MAX_CHARS", "32768")
    reset_settings_cache()
    try:
        yield
    finally:
        reset_settings_cache()


@pytest.fixture(autouse=True)
def _fake_job_nonce_store(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep the suite's job-signature checks off the live Redis server.

    The worker burns a job nonce in Redis before executing anything. Every test
    gets a fresh in-memory server instead, because the process-wide client would
    otherwise bind to the first test's event loop. The real server's SET NX / TTL
    semantics are covered by ``tests/test_job_auth.py`` under the
    ``redis_integration`` marker, the same split the egress quarantine tests use.
    """
    from fakeredis import FakeAsyncRedis

    client = FakeAsyncRedis(decode_responses=True)
    monkeypatch.setattr("agent.runtime.get_redis", lambda *_args, **_kwargs: client)
    yield
    # In-memory only: nothing to close, and the object dies with the test.


@pytest.fixture(autouse=True)
def _disable_rate_limiting(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep the suite from spending the development Redis rate-limit budget.

    The limiter has its own tests, which enable it explicitly and inject a
    deterministic store. Every other test asserts application behaviour, not
    request budgets, so a real bucket would make the suite order-dependent.
    """
    from settings import reset_settings_cache

    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    reset_settings_cache()
    try:
        yield
    finally:
        reset_settings_cache()


@pytest.fixture(autouse=True)
def _disable_approval_event_publish(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep tests off the live Redis pub/sub bus.

    Approval events are best-effort; the unit tests that assert publication
    replace these stubs with their own recorder. Without this, the first test
    that decides a ticket would create a loop-bound Redis client that a later
    test's event loop cannot reuse.
    """

    async def noop(*_args: object, **_kwargs: object) -> bool:
        return True

    for target in (
        "agent.runtime.publish_approval_event",
        "agent.demo.scenarios.publish_approval_event",
        "gateway.routers.approvals.publish_approval_event",
    ):
        monkeypatch.setattr(target, noop)
    yield


@pytest.fixture(autouse=True)
def _disable_tool_resume_enqueue(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep the suite from enqueueing ARQ jobs onto a live worker queue.

    Approval routes enqueue a resume job after committing. Tests exercise the
    database state machine directly, so the enqueue bridge must stay inert.
    """
    from settings import reset_settings_cache

    monkeypatch.setenv("TOOL_RESUME_AUTO_ENQUEUE", "false")
    reset_settings_cache()
    try:
        yield
    finally:
        reset_settings_cache()
