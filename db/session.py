"""Async PostgreSQL connection management.

The engine is created lazily so that importing this module (for example, inside a
CLI or a test collector) never opens sockets or requires a running database.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from db.models import (
    AUDIT_APPEND_ONLY_DDL,
    AUDIT_EVENT_VOCABULARY_DDL,
    ESCROW_KIND_DDL,
    SCHEMA_INIT_LOCK_ID,
    TENANT_SCOPE_DDL,
    Base,
)
from settings import Settings, get_settings

logger = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def create_engine(settings: Settings | None = None) -> AsyncEngine:
    """Build a new async engine from configuration (does not connect eagerly)."""
    config = settings or get_settings()
    engine = create_async_engine(
        config.database_url,
        echo=config.database_echo,
        pool_size=config.database_pool_size,
        max_overflow=config.database_max_overflow,
        pool_recycle=config.database_pool_recycle_seconds,
        pool_pre_ping=True,
        connect_args={
            "timeout": config.database_connect_timeout_seconds,
            "server_settings": {
                "application_name": config.app_name,
                # Canonical UTC storage keeps audit-chain hashes reproducible.
                "timezone": "UTC",
            },
        },
        future=True,
    )
    logger.debug(
        "Created async database engine",
        extra={"database_url": config.redacted_database_url},
    )
    return engine


def get_engine() -> AsyncEngine:
    """Return the process-wide engine, creating it on first use."""
    global _engine
    if _engine is None:
        _engine = create_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the process-wide session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Transactional unit of work: commit on success, roll back on error."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        except BaseException:
            await session.rollback()
            raise
        await session.commit()


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a transactional session."""
    # FastAPI finalises yield-dependencies through its AsyncExitStack on every
    # exit path (response, error, disconnect); pylint cannot see that.
    # pylint: disable-next=contextmanager-generator-missing-cleanup
    async with session_scope() as session:
        yield session


async def init_models(engine: AsyncEngine | None = None) -> None:
    """Create tables, indexes and sequences if they do not exist yet.

    An advisory lock makes this safe when several gateway/worker replicas boot
    simultaneously. Schema *changes* belong in Alembic migrations; this routine
    only bootstraps a fresh database.
    """
    target = engine or get_engine()
    async with target.begin() as connection:
        await connection.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": SCHEMA_INIT_LOCK_ID},
        )
        await connection.run_sync(Base.metadata.create_all)
        # `after_create` only fires for new tables; re-apply the audit guard so
        # upgraded databases enforce append-only too.
        for statement in AUDIT_APPEND_ONLY_DDL:
            await connection.execute(text(statement))
        # ADR-015: create_all cannot add columns to an existing table, so the
        # tenant columns and indexes are applied idempotently on every boot.
        for statement in TENANT_SCOPE_DDL:
            await connection.execute(text(statement))
        # ADR-005 decision 7: widen the audit event vocabulary for databases
        # created before ESCROW_ACCESSED existed.
        for statement in AUDIT_EVENT_VOCABULARY_DDL:
            await connection.execute(text(statement))
        # ...and widen the escrow kind for databases created before
        # egress_delivered existed.
        for statement in ESCROW_KIND_DDL:
            await connection.execute(text(statement))
    logger.info(
        "Database schema ready",
        extra={"tables": sorted(Base.metadata.tables)},
    )


async def ping() -> bool:
    """Liveness probe for the database; never raises."""
    try:
        async with get_engine().connect() as connection:
            await connection.execute(text("SELECT 1"))
    except (SQLAlchemyError, OSError) as exc:
        logger.warning("Database ping failed", extra={"error": str(exc)})
        return False
    return True


async def dispose_engine() -> None:
    """Flush the connection pool and reset module state (shutdown/tests)."""
    global _engine, _session_factory
    engine, _engine = _engine, None
    _session_factory = None
    if engine is not None:
        await engine.dispose()
        logger.debug("Database engine disposed")
