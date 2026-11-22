"""Stateless MCP over the guarded tool catalog (ADR-028, IDEA-107).

The MCP surface is a *view* of the approved catalog, never a discovery
mechanism: ``tools/list`` serves the entry's pinned description and input
schema, and ``tools/call`` runs the same gates the native routes run. A tool
that is registered in code but absent from ``docs/tools/v1.json`` is invisible
here, and a name the catalog does not hold is refused with the same
``-32003`` code the native path uses.

The handlers read the caller from a context variable the gateway's Bearer wall
sets for the duration of one request (see :mod:`gateway.routers.mcp`), so no
identity is ever taken from the JSON-RPC arguments.
"""

from __future__ import annotations

import json
import logging
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Final

from mcp import types
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import MCPError
from sqlalchemy.ext.asyncio import AsyncSession

from agent.tools.catalog import CatalogTool, get_tool_catalog
from agent.tools.decorator import AgentContext, ToolStatus, list_tools
from agent.tools.errors import (
    ToolCatalogUnavailableError,
    ToolError,
    ToolNotFoundError,
    ToolNotInCatalogError,
)
from agent.tools.execution import request_tool_execution

logger = logging.getLogger(__name__)

#: Name the MCP client sees in ``server/discover``.
SERVER_NAME: Final[str] = "bastion"


@dataclass(frozen=True, slots=True)
class McpCaller:
    """The authenticated caller a handler executes on behalf of."""

    actor_id: str
    tenant_id: str
    roles: frozenset[str]
    session_id: str
    actor_type: str = "human"
    agent_id: str | None = None
    owner_sub: str | None = None
    #: ``None`` for a human; the registry allowlist for an agent.
    allowed_tools: frozenset[str] | None = None
    #: The request-scoped session, so a tool call joins the auth transaction.
    session: AsyncSession | None = None

    def agent_context(self) -> AgentContext:
        return AgentContext(
            actor_id=self.actor_id,
            tenant_id=self.tenant_id,
            roles=self.roles,
            session_id=self.session_id,
            actor_type=self.actor_type,
            agent_id=self.agent_id,
            owner_sub=self.owner_sub,
            allowed_tools=self.allowed_tools,
        )


_CALLER: ContextVar[McpCaller | None] = ContextVar("mcp_caller", default=None)


def current_caller() -> McpCaller | None:
    """The caller the Bearer wall resolved for this request, if any."""
    return _CALLER.get()


def set_caller(caller: McpCaller) -> None:
    _CALLER.set(caller)


def reset_caller() -> None:
    _CALLER.set(None)


def _input_schema(entry: CatalogTool) -> dict[str, Any]:
    """Project the catalog's argument table into the JSON Schema MCP expects."""
    properties = {name: {"type": spec["type"]} for name, spec in entry.arguments.items()}
    required = [name for name, spec in entry.arguments.items() if spec["required"]]
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return schema


def _tool(entry: CatalogTool) -> types.Tool:
    return types.Tool(
        name=entry.name,
        description=entry.description,
        input_schema=_input_schema(entry),
        _meta={
            "server": entry.server,
            "description_hash": entry.description_hash,
            "input_schema_hash": entry.input_schema_hash,
        },
    )


def catalog_tools() -> tuple[types.Tool, ...]:
    """The MCP view of the catalog: approved *and* still registered.

    A catalog that cannot be read exposes no tools rather than all of them,
    which is the same fail-closed rule Gate 1 applies at call time.
    """
    try:
        catalog = get_tool_catalog()
    except ToolCatalogUnavailableError:
        logger.warning("MCP tools/list served empty: catalog unavailable")
        return ()
    registered = {definition.name for definition in list_tools()}
    return tuple(
        _tool(entry) for name, entry in sorted(catalog.tools.items()) if name in registered
    )


async def on_list_tools(
    _context: Any, _params: types.PaginatedRequestParams | None = None
) -> types.ListToolsResult:
    """Serve the approved catalog text; the live registry never reaches a client."""
    return types.ListToolsResult(tools=list(catalog_tools()))


def _text(payload: dict[str, Any]) -> types.TextContent:
    return types.TextContent(type="text", text=json.dumps(payload, sort_keys=True))


async def on_call_tool(_context: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    """Run one guarded tool call through the shared execution state machine."""
    caller = current_caller()
    if caller is None or caller.session is None:
        # The Bearer wall refuses before dispatch, so this is a wiring mistake.
        raise MCPError(-32603, "no authenticated caller for this request")

    try:
        result = await request_tool_execution(
            caller.session,
            tool_name=params.name,
            arguments=dict(params.arguments or {}),
            context=caller.agent_context(),
        )
    except (ToolNotInCatalogError, ToolNotFoundError) as exc:
        # Both are "unknown tool" to a caller, and the catalog is the outer gate.
        code = getattr(exc, "code", -32003)
        raise MCPError(code, str(exc)) from exc
    except ToolError as exc:
        return types.CallToolResult(content=[_text({"error": str(exc)})], is_error=True)

    payload = result.to_payload()
    return types.CallToolResult(
        content=[_text(payload)],
        structured_content=payload,
        is_error=result.status in {ToolStatus.REJECTED, ToolStatus.FAILED},
    )


def build_server() -> Server[Any]:
    """The low-level MCP server, wired with the catalog handlers."""
    return Server(
        name=SERVER_NAME,
        version="1.0.0",
        instructions=(
            "Bastion's approved tools. tools/list is the allow-list; a call that is "
            "not in it is refused before any execution."
        ),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def new_session_id() -> str:
    """Identifier a tool call's ledger rows group under when the client sends none."""
    return f"mcp:{uuid.uuid4()}"
