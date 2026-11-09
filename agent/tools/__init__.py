"""Guarded tool definitions and the declarative ``@tool`` guard (ADR-003).

Declaring a tool registers it; the execution guard in
:mod:`agent.tools.execution` enforces RBAC and four-eyes suspension.
"""

# Importing the built-ins registers them (registration side effect).
from agent.tools import builtin
from agent.tools.decorator import (
    AgentContext,
    ToolArgumentError,
    ToolAuthorizationError,
    ToolDefinition,
    ToolDefinitionError,
    ToolError,
    ToolExecutionResult,
    ToolInvocationError,
    ToolNotFoundError,
    ToolStatus,
    available_tools,
    get_tool,
    list_tools,
    tool,
    tool_registry,
    unregister_tool,
)

__all__ = [
    "AgentContext",
    "ToolArgumentError",
    "ToolAuthorizationError",
    "ToolDefinition",
    "ToolDefinitionError",
    "ToolError",
    "ToolExecutionResult",
    "ToolInvocationError",
    "ToolNotFoundError",
    "ToolStatus",
    "available_tools",
    "builtin",
    "get_tool",
    "list_tools",
    "tool",
    "tool_registry",
    "unregister_tool",
]
