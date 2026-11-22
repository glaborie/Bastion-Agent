"""Non-human principals: agent registry lookup and ingress enforcement (ADR-027).

A ``client_credentials`` token from a per-agent Keycloak client is accepted on
the API only when a registry row exists, is ``active``, is inside its expiry
window, belongs to the token's tenant and allows the requested path. The row is
also the only allow switch, so suspending it denies the next call before any
work is enqueued; there is no second quarantine table to keep in sync.

Agents never reach a dashboard session: :func:`authorize_agent` admits the
``/v1/`` API prefixes only, and the ingress rejects an agent token on the
session routes before a session record could be written.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Final

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from agent.tools.catalog import get_tool_catalog
from agent.tools.errors import ToolCatalogUnavailableError
from db.audit import AuditChainError, append_audit_event
from db.models import AgentRegistry, AuditEventType, utcnow
from gateway.auth.oidc import Principal

logger = logging.getLogger(__name__)

#: The only paths an agent token may call. Everything else in this application
#: is session-authenticated (dashboard, approval queue, audit reads).
AGENT_API_PREFIXES: Final[tuple[str, ...]] = ("/v1/", "/mcp")


@dataclass(frozen=True, slots=True)
class AgentDenial(Exception):
    """A registry refusal, carrying the stable reason written to the ledger."""

    reason: str

    def __str__(self) -> str:
        return self.reason


def effective_tools(entry: AgentRegistry) -> frozenset[str]:
    """The catalog intersected with the agent's allowlist.

    The catalog stays the outer gate: an allowlisted name that is not approved
    is dropped here and would still be refused by Gate 1 at call time. An empty
    allowlist means no tools, never all of them.
    """
    try:
        approved = get_tool_catalog().names()
    except ToolCatalogUnavailableError:
        return frozenset()
    return frozenset(name for name in entry.allowed_tools if name in approved)


async def load_agent(session: AsyncSession, agent_id: str) -> AgentRegistry | None:
    """The registry row for ``agent_id``, if one exists."""
    statement = select(AgentRegistry).where(AgentRegistry.agent_id == agent_id)
    return (await session.execute(statement)).scalar_one_or_none()


def _refusal(entry: AgentRegistry | None, path: str, tenant_id: str) -> str | None:
    """The stable denial reason, or ``None`` when the call may proceed."""
    if entry is None:
        return "unregistered_agent"
    if not entry.is_usable:
        return (
            "agent_suspended"
            if not entry.is_usable and entry.status.value == "suspended"
            else "agent_expired"
        )
    if entry.tenant_id != tenant_id:
        return "tenant_mismatch"
    if not any(path.startswith(prefix) for prefix in AGENT_API_PREFIXES):
        return "agent_session_route"
    return None


async def _record_denial(
    session: AsyncSession,
    principal: Principal,
    agent_id: str,
    reason: str,
    owner_sub: str | None,
) -> None:
    """Commit the visible denial row before the request is refused.

    Authentication runs before the handler writes anything, so committing here
    cannot publish unrelated work; the later 403 rolls back nothing that
    matters. A ledger write that itself fails must not turn a refusal into a
    pass: the 403 is raised either way, and the failure is logged.
    """
    try:
        await append_audit_event(
            session,
            actor_id=principal.subject,
            tenant_id=principal.tenant_id,
            actor_type="agent",
            agent_id=agent_id,
            owner_sub=owner_sub,
            event_type=AuditEventType.SECURITY_INCIDENT,
            payload={"agent_id": agent_id},
            metadata_json={"reason": reason, "stage": "agent_ingress"},
            timestamp=utcnow(),
        )
        await session.commit()
    except (AuditChainError, SQLAlchemyError):
        logger.exception(
            "Could not record the agent denial; refusing anyway",
            extra={"agent_id": agent_id, "reason": reason},
        )


async def authorize_agent(session: AsyncSession, principal: Principal, path: str) -> AgentRegistry:
    """Admit an agent token on the API or refuse it with a ledger row.

    Returns the registry row so the caller can attach the allowlist, budget key
    and owner to the request context.
    """
    agent_id = principal.agent_id or ""
    entry = await load_agent(session, agent_id)
    reason = _refusal(entry, path, principal.tenant_id)
    if reason is not None:
        await _record_denial(
            session, principal, agent_id, reason, entry.owner_sub if entry else None
        )
        logger.warning(
            "Agent request refused at ingress",
            extra={"agent_id": agent_id, "reason": reason, "path": path},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"agent principal refused: {reason}",
        )
    assert entry is not None  # _refusal returns a reason when entry is None
    return entry
