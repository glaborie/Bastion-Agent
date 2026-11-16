"""Provision the least-privilege runtime database role (IDEA-062, ADR-005).

The request-serving processes connect as this role: it is not a superuser, owns
nothing and may only read and append the audit ledger. The schema owner (the
``migrate`` service, or the test fixture) calls :func:`bootstrap_runtime_role`
after ``init_models`` so grants land on tables that already exist.

Identifiers come from deployment configuration, never from a request, and are
quoted by the server (``quote_ident``/``quote_literal``) rather than by string
interpolation.
"""

from __future__ import annotations

import re
from typing import Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

#: Role names accepted from configuration. The grammar matches
#: ``db.tenancy``'s narrow shape: a leading lowercase letter or underscore.
ROLE_NAME_PATTERN: Final = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class RoleBootstrapError(RuntimeError):
    """The runtime role cannot be provisioned from the supplied configuration."""


async def _quoted(connection: AsyncConnection, function: str, value: str) -> str:
    quoted = (
        await connection.execute(text(f"SELECT {function}(:value)"), {"value": value})
    ).scalar_one()
    return str(quoted)


async def bootstrap_runtime_role(
    connection: AsyncConnection,
    *,
    role: str,
    password: str,
    database: str,
) -> None:
    """Create or update the runtime role and grant only what the app needs.

    ``audit_logs`` gets ``SELECT, INSERT`` and nothing else; every other table
    keeps the DML the application already performs. ``UPDATE``/``DELETE`` are
    revoked even if a previous run granted them, so the function is idempotent.
    """
    if not ROLE_NAME_PATTERN.fullmatch(role):
        raise RoleBootstrapError(f"invalid runtime role name {role!r}")
    if not password:
        raise RoleBootstrapError("runtime role password must not be empty")

    role_lit = await _quoted(connection, "quote_ident", role)
    password_lit = await _quoted(connection, "quote_literal", password)
    database_lit = await _quoted(connection, "quote_ident", database)

    existing = (
        await connection.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role}
        )
    ).scalar_one_or_none()
    if existing is None:
        await connection.execute(text(f"CREATE ROLE {role_lit} LOGIN"))
    await connection.execute(
        text(
            f"ALTER ROLE {role_lit} WITH LOGIN NOSUPERUSER NOCREATEDB "
            f"NOCREATEROLE PASSWORD {password_lit}"
        )
    )

    await connection.execute(text(f"GRANT CONNECT ON DATABASE {database_lit} TO {role_lit}"))
    await connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {role_lit}"))
    await connection.execute(text(f"REVOKE CREATE ON SCHEMA public FROM {role_lit}"))

    # Non-audit tables keep the DML the runtime already performs. TRUNCATE is
    # not granted anywhere: nothing in the application truncates a table.
    await connection.execute(
        text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role_lit}")
    )
    await connection.execute(
        text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role_lit}")
    )

    # The ledger is append-only even for the runtime: insert and read only.
    await connection.execute(text(f"REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM {role_lit}"))
    await connection.execute(text(f"GRANT SELECT, INSERT ON audit_logs TO {role_lit}"))
    await connection.execute(
        text(f"GRANT EXECUTE ON FUNCTION bastion_audit_logs_append_only() TO {role_lit}")
    )
