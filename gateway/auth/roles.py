"""Role vocabulary and satisfiability rules (ADR-003).

Roles are issued by Keycloak in ``realm_access.roles``. This module is the only
place that decides what a granted role set may do, so the API, the dashboard and
the tool guard cannot drift apart.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Final


class Role(StrEnum):
    """The four roles defined by HANDOVER_SPEC §3.1."""

    ADMIN = "admin"
    OPERATOR = "operator"
    ANALYST = "analyst"
    READONLY = "readonly"


ROLE_NAMES: frozenset[str] = frozenset(member.value for member in Role)

#: Read surfaces of the control plane: the dashboard and its pages, the audit
#: ledger and its chain check, the session inspector, the incident panel and the
#: approval queue as a list. Every known role may look (ADR-007 decision 9).
READ_ROLES: Final[tuple[str, ...]] = (
    Role.ADMIN.value,
    Role.OPERATOR.value,
    Role.ANALYST.value,
    Role.READONLY.value,
)

#: Acting: the four-eyes decision, the demo console, the handoff queue and its
#: acknowledgement. An action always needs an operator or the admin superset.
WRITE_ROLES: Final[tuple[str, ...]] = (Role.ADMIN.value, Role.OPERATOR.value)

#: Chat, on the API and the page alike: an analyst may ask the assistant a
#: question, a readonly principal may not spend tokens or write a turn.
CHAT_ROLES: Final[tuple[str, ...]] = (
    Role.ADMIN.value,
    Role.OPERATOR.value,
    Role.ANALYST.value,
)

#: ``admin`` is a superset by definition (break-glass operator). The other three
#: are independent grants: ``operator`` is *not* implicitly ``analyst``.
ADMIN_ROLE: str = Role.ADMIN.value


def normalise_roles(values: Iterable[object]) -> frozenset[str]:
    """Keep known roles only, dropping Keycloak's default roles and junk claims."""
    granted: set[str] = set()
    for value in values:
        if isinstance(value, str):
            candidate = value.strip().lower()
            if candidate in ROLE_NAMES:
                granted.add(candidate)
    return frozenset(granted)


def is_satisfied(granted: frozenset[str] | set[str], required: str) -> bool:
    """True when ``granted`` contains ``required`` (or the admin superset)."""
    return required in granted or ADMIN_ROLE in granted


def any_satisfied(granted: frozenset[str] | set[str], required: Iterable[str]) -> bool:
    """True when at least one required role is satisfied (any-of semantics)."""
    return any(is_satisfied(granted, role) for role in required)
