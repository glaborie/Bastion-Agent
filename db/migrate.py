"""One-shot owner migration: schema + runtime-role grants (IDEA-062).

Run only by the ``migrate`` compose service (or CI) whose ``DATABASE_URL`` is
the owner credential. The gateway and worker never run this and never see that
credential; they connect as the role provisioned here, which owns nothing and
can only read and append the audit ledger.
"""

from __future__ import annotations

import asyncio
import logging
import os

from sqlalchemy import text

from db.roles import RoleBootstrapError, bootstrap_runtime_role
from db.session import dispose_engine, get_engine, init_models

logger = logging.getLogger(__name__)


async def migrate() -> None:
    """Create/upgrade the schema, then grant the runtime role its privileges."""
    role = os.getenv("RUNTIME_DB_USER", "")
    password = os.getenv("RUNTIME_DB_PASSWORD", "")
    if not role or not password:
        raise RoleBootstrapError("RUNTIME_DB_USER and RUNTIME_DB_PASSWORD are required")

    await init_models()
    engine = get_engine()
    try:
        async with engine.begin() as connection:
            database = (await connection.execute(text("SELECT current_database()"))).scalar_one()
            await bootstrap_runtime_role(
                connection, role=role, password=password, database=str(database)
            )
    finally:
        await dispose_engine()
    logger.info("Database schema and runtime role are ready", extra={"runtime_role": role})


def main() -> int:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    asyncio.run(migrate())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
