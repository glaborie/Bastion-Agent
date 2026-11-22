"""Guarded tool definitions and the declarative ``@tool`` guard (ADR-003).

Declaring a tool registers it; the execution guard in
:mod:`agent.tools.execution` enforces RBAC and four-eyes suspension, and the
catalog in :mod:`agent.tools.catalog` enforces the ADR-009 Gate 1 allow-list.
"""

# Importing the built-ins registers them (registration side effect).
from agent.tools import builtin
from agent.tools.catalog import (
    CatalogTool,
    ToolCatalog,
    compare_catalog,
    get_tool_catalog,
    load_catalog,
    override_tool_catalog,
    reset_tool_catalog_cache,
)
from agent.tools.decorator import (
    AgentContext,
    ToolDefinition,
    ToolExecutionResult,
    ToolHandler,
    ToolStatus,
    available_tools,
    definitions_for,
    get_tool,
    is_valid_tool_name,
    list_tools,
    tool,
    tool_registry,
    unregister_tool,
    verify_registry,
)
from agent.tools.errors import (
    TOOL_NOT_IN_CATALOG_CODE,
    ToolArgumentError,
    ToolAuthorizationError,
    ToolCatalogDriftError,
    ToolCatalogError,
    ToolCatalogUnavailableError,
    ToolDefinitionError,
    ToolError,
    ToolInvocationError,
    ToolNotFoundError,
    ToolNotInCatalogError,
)

__all__ = [
    "TOOL_NOT_IN_CATALOG_CODE",
    "AgentContext",
    "CatalogTool",
    "ToolArgumentError",
    "ToolAuthorizationError",
    "ToolCatalog",
    "ToolCatalogDriftError",
    "ToolCatalogError",
    "ToolCatalogUnavailableError",
    "ToolDefinition",
    "ToolDefinitionError",
    "ToolError",
    "ToolExecutionResult",
    "ToolHandler",
    "ToolInvocationError",
    "ToolNotFoundError",
    "ToolNotInCatalogError",
    "ToolStatus",
    "available_tools",
    "builtin",
    "compare_catalog",
    "definitions_for",
    "get_tool",
    "get_tool_catalog",
    "is_valid_tool_name",
    "list_tools",
    "load_catalog",
    "override_tool_catalog",
    "reset_tool_catalog_cache",
    "tool",
    "tool_registry",
    "unregister_tool",
    "verify_registry",
]
