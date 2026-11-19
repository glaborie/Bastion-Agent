"""One-shot owner migration: schema + runtime-role grants (IDEA-062).

Run only by the ``migrate`` compose service (or CI) whose ``DATABASE_URL`` is
the owner credential. The gateway and worker never run this and never see that
credential; they connect as the role provisioned here, which owns nothing and
can only read and append the audit ledger.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from sqlalchemy import text

from db.agents import REGISTRY_SEED_PATH, load_registry_seed
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
            await seed_agent_registry(connection)
    finally:
        await dispose_engine()
    logger.info("Database schema and runtime role are ready", extra={"runtime_role": role})


_SEED_AGENT = text(
    """
    INSERT INTO agent_registry (
        agent_id, owner_sub, tenant_id, status, expires_at,
        allowed_tools, allowed_route_aliases, budget_key, created_at, updated_at
    ) VALUES (
        :agent_id, :owner_sub, :tenant_id, :status, NULL,
        CAST(:allowed_tools AS jsonb), CAST(:allowed_route_aliases AS jsonb),
        :budget_key, now(), now()
    )
    ON CONFLICT (agent_id) DO NOTHING
    """
)


async def seed_agent_registry(connection: Any) -> None:
    """Insert registry rows the operator has not created yet (ADR-027).

    Deliberately insert-only: a row that already exists is the runtime truth and
    is never overwritten by a file, so suspending an agent survives a redeploy.
    """
    if not REGISTRY_SEED_PATH.is_file():
        logger.warning("Agent registry seed is absent; no rows seeded")
        return
    entries = load_registry_seed(REGISTRY_SEED_PATH)
    for entry in entries:
        await connection.execute(
            _SEED_AGENT,
            {
                "agent_id": entry["agent_id"],
                "owner_sub": entry.get("owner_sub", ""),
                "tenant_id": entry.get("tenant_id", "default"),
                "status": entry.get("status", "active"),
                "allowed_tools": json.dumps(entry.get("allowed_tools") or []),
                "allowed_route_aliases": json.dumps(entry.get("allowed_route_aliases") or []),
                "budget_key": entry.get("budget_key") or entry["agent_id"],
            },
        )
    logger.info("Agent registry seed applied", extra={"rows": len(entries)})


def main() -> int:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    asyncio.run(migrate())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
