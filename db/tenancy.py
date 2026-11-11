"""Tenant identifier validation shared by the gateway, worker and database.

Tenant ids become part of Redis keys, SQL predicates and log metadata, so they
are validated once here instead of at every call site. The grammar is deliberately
narrow: a leading alphanumeric followed by letters, digits, dot, underscore or
hyphen. Colons are excluded so a tenant cannot forge an extra key segment.

The identifier is always derived from a validated OIDC claim (ADR-015); it is
never accepted from a request body, header or query parameter.
"""

from __future__ import annotations

import re
from typing import Final

#: Maximum stored length, matching ``VARCHAR(64)`` on the tenant columns.
MAX_TENANT_ID_LENGTH: Final[int] = 64

_TENANT_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
    rf"^[A-Za-z0-9][A-Za-z0-9._-]{{0,{MAX_TENANT_ID_LENGTH - 1}}}$"
)


class TenantIdError(ValueError):
    """A tenant identifier is missing or outside the accepted grammar."""


def normalise_tenant_id(value: object) -> str:
    """Return a validated tenant id or raise :class:`TenantIdError`.

    ``object`` is intentional: callers pass values straight from a JWT claim,
    where the type is untrusted.
    """
    if not isinstance(value, str):
        raise TenantIdError("tenant id must be a string")
    tenant = value.strip()
    if not tenant:
        raise TenantIdError("tenant id must not be empty")
    if not _TENANT_ID_PATTERN.fullmatch(tenant):
        raise TenantIdError(
            "tenant id must match [A-Za-z0-9][A-Za-z0-9._-]* "
            f"(max {MAX_TENANT_ID_LENGTH} characters)"
        )
    return tenant


def is_valid_tenant_id(value: object) -> bool:
    """Boolean form for tests and diagnostics; never raises."""
    try:
        normalise_tenant_id(value)
    except TenantIdError:
        return False
    return True
