"""Tool-guard error taxonomy (ADR-003, ADR-009 Gate 1).

Kept in its own module so the registry (:mod:`agent.tools.decorator`) and the
allow-list (:mod:`agent.tools.catalog`) can both use the same exceptions without
importing each other. Every error derives from :class:`ToolError`; callers that
only care about "the guard refused" can catch that one class.
"""

from __future__ import annotations

from typing import Final

#: JSON-RPC code returned for a tool that is not in the approved catalog
#: (ADR-009 Gate 1). Also used for a name that is not registered at all: to a
#: caller both are "unknown tool".
TOOL_NOT_IN_CATALOG_CODE: Final[int] = -32003


class ToolError(RuntimeError):
    """Base class for guard failures."""


class ToolCatalogError(ToolError):
    """Base class for ADR-009 Gate 1 failures (allow-list or catalog state)."""


class ToolNotInCatalogError(ToolCatalogError):
    """The tool is registered in code but absent from the approved catalog."""

    def __init__(self, tool_name: str) -> None:
        super().__init__(f"tool {tool_name!r} is not in the approved tool catalog")
        self.tool_name = tool_name
        self.code: int = TOOL_NOT_IN_CATALOG_CODE


class ToolCatalogUnavailableError(ToolCatalogError):
    """The catalog cannot be read or parsed; every tool call fails closed."""


class ToolCatalogDriftError(ToolCatalogError):
    """A catalog entry no longer matches its registered definition."""


class ToolDefinitionError(ToolError):
    """A ``@tool`` declaration is invalid (raised at import time)."""


class ToolNotFoundError(ToolError):
    """No tool with the requested name is registered."""


class ToolArgumentError(ToolError):
    """Caller-supplied arguments do not match the declaration."""


class ToolAuthorizationError(ToolError):
    """The caller's roles do not satisfy the tool's ``required_role``."""

    def __init__(self, tool_name: str, required_role: str) -> None:
        super().__init__(f"role {required_role!r} is required to call tool {tool_name!r}")
        self.tool_name = tool_name
        self.required_role = required_role


class ToolInvocationError(ToolError):
    """The tool handler raised while executing."""

    def __init__(self, tool_name: str, error_type: str) -> None:
        super().__init__(f"tool {tool_name!r} failed ({error_type})")
        self.tool_name = tool_name
        self.error_type = error_type
