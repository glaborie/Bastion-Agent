"""Least-privilege runtime database role (IDEA-062, ADR-005 decision 3).

The test provisions the role through the owner engine, then connects with the
separate app DSN and proves the ledger is read/append only and break-glass
requires owner DDL. It runs only when ``TEST_DATABASE_APP_URL`` is set (CI sets
it; a local run can export it against a disposable PostgreSQL).
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from db.roles import bootstrap_runtime_role
from tests.conftest import requires_database

APP_DATABASE_URL = os.getenv("TEST_DATABASE_APP_URL", "")

pytestmark = [
    pytest.mark.integration,
    requires_database,
    pytest.mark.skipif(not APP_DATABASE_URL, reason="TEST_DATABASE_APP_URL is not set"),
]

_TRIGGER = "trg_audit_logs_append_only"
_INSERT = """
INSERT INTO audit_logs (
    id, timestamp, tenant_id, actor_id, event_type,
    payload_hash, hash_version, metadata_hash, metadata_json,
    previous_hash, record_hash
) VALUES (
    nextval('audit_logs_id_seq'), now(), 'acme', 'app', 'INPUT_RECEIVED',
    :payload, 1, NULL, '{}'::jsonb, :previous, :record
)
"""


async def _bootstrap(engine: AsyncEngine) -> None:
    app = make_url(APP_DATABASE_URL)
    async with engine.begin() as connection:
        database = (await connection.execute(text("SELECT current_database()"))).scalar_one()
        await bootstrap_runtime_role(
            connection,
            role=str(app.username),
            password=str(app.password),
            database=str(database),
        )


async def _refused(engine: AsyncEngine, statement: str) -> None:
    with pytest.raises(DBAPIError):
        async with engine.begin() as connection:
            await connection.execute(text(statement))


async def test_runtime_role_is_non_owner_and_cannot_rewrite_the_ledger(
    db_engine: AsyncEngine,
) -> None:
    await _bootstrap(db_engine)
    app_engine = create_async_engine(APP_DATABASE_URL, poolclass=NullPool)
    try:
        async with app_engine.connect() as connection:
            identity = (
                await connection.execute(
                    text(
                        "SELECT rolsuper, rolcreatedb, rolcreaterole, rolcanlogin "
                        "FROM pg_roles WHERE rolname = current_user"
                    )
                )
            ).one()
            assert identity == (False, False, False, True)

            owned = (
                await connection.execute(
                    text(
                        "SELECT count(*) FROM pg_class "
                        "WHERE relkind = 'r' "
                        "AND relnamespace = 'public'::regnamespace "
                        "AND pg_get_userbyid(relowner) = current_user"
                    )
                )
            ).scalar_one()
            assert owned == 0

            privileges = (
                await connection.execute(
                    text(
                        "SELECT "
                        "has_table_privilege(current_user, 'audit_logs', 'INSERT'), "
                        "has_table_privilege(current_user, 'audit_logs', 'UPDATE'), "
                        "has_table_privilege(current_user, 'audit_logs', 'DELETE'), "
                        "has_table_privilege(current_user, 'audit_logs', 'TRUNCATE'), "
                        "has_table_privilege("
                        "current_user, 'pending_approvals', 'INSERT,UPDATE,DELETE')"
                    )
                )
            ).one()
            assert privileges == (True, False, False, False, True)

            await connection.execute(
                text(_INSERT), {"payload": "b" * 64, "previous": "0" * 64, "record": "a" * 64}
            )
            await connection.commit()
            count = (await connection.execute(text("SELECT count(*) FROM audit_logs"))).scalar_one()
            assert count == 1

        # The ledger itself is the one table the runtime may not rewrite.
        await _refused(app_engine, "UPDATE audit_logs SET actor_id = 'x'")
        await _refused(app_engine, "DELETE FROM audit_logs")
        await _refused(app_engine, "TRUNCATE audit_logs")
        # Break-glass is owner DDL; the runtime cannot disable the trigger.
        await _refused(app_engine, f"ALTER TABLE audit_logs DISABLE TRIGGER {_TRIGGER}")

        # ...and the owner can.
        async with db_engine.begin() as owner:
            await owner.execute(text(f"ALTER TABLE audit_logs DISABLE TRIGGER {_TRIGGER}"))
            await owner.execute(text(f"ALTER TABLE audit_logs ENABLE TRIGGER {_TRIGGER}"))
    finally:
        await app_engine.dispose()
