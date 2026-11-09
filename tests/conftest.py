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
from collections.abc import AsyncIterator

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

from db.models import Base

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
        await connection.execute(
            text("TRUNCATE TABLE audit_logs, pending_approvals RESTART IDENTITY CASCADE")
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
