"""Declarative tool guard: definitions, RBAC and argument validation (ADR-003).

A tool is declared once, next to its implementation::

    @tool(
        name="execute_file_write",
        description="Writes data to storage",
        read_only=False,
        required_role="operator",
    )
    async def execute_file_write(path: str, content: str, context: AgentContext) -> dict: ...

The decorator records the security attributes (``read_only``, ``required_role``),
introspects the JSON arguments and registers the definition in a process-wide
registry. The guard itself lives in :mod:`agent.tools.execution`; this module is
deliberately free of database and network access so a tool definition can never
fail open at import time.

Two rules are enforced at decoration time, not at call time:

* the handler must be ``async`` and must take a ``context: AgentContext``;
* every other parameter must be annotated with a JSON type (``str``, ``int``,
  ``float`` or ``bool``), so the model-facing schema and the runtime check
  cannot drift.
"""

from __future__ import annotations

import inspect
import json
import logging
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final, TypeAlias, get_type_hints

from gateway.auth.roles import ROLE_NAMES, is_satisfied, normalise_roles

logger = logging.getLogger(__name__)

#: A tool handler: async, keyword-callable, receives ``context`` alongside its
#: declared JSON arguments.
ToolHandler: TypeAlias = Callable[..., Awaitable[Any]]

_TOOL_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

#: Supported parameter annotations and their JSON-schema names.
_JSON_TYPES: Final[dict[type, str]] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
}


class ToolError(RuntimeError):
    """Base class for guard failures."""


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


class ToolStatus(StrEnum):
    """Terminal or suspended outcome of a guarded tool call."""

    EXECUTED = "executed"
    APPROVAL_PENDING = "approval_pending"
    REJECTED = "rejected"
    EXPIRED = "expired"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AgentContext:
    """The authenticated identity a tool executes on behalf of.

    Constructed by the runtime from a validated token or dashboard session; a
    tool must never read caller identity from its JSON arguments.

    ``actor_id`` **must be the OIDC subject** (the JWT ``sub`` claim), never a
    username or email. Four-eyes compares it byte-for-byte with the approver's
    subject, so feeding it a different identity namespace would silently let an
    initiator approve their own ticket.
    """

    actor_id: str
    roles: frozenset[str]
    session_id: str
    request_id: str | None = None

    def __post_init__(self) -> None:
        actor = (self.actor_id or "").strip()
        session = (self.session_id or "").strip()
        if not actor:
            raise ValueError("actor_id is required for a tool context")
        if not session:
            raise ValueError("session_id is required for a tool context")
        object.__setattr__(self, "actor_id", actor)
        object.__setattr__(self, "session_id", session)
        object.__setattr__(self, "roles", normalise_roles(self.roles))


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Immutable description of one guarded tool."""

    name: str
    description: str
    read_only: bool
    required_role: str | None
    handler: ToolHandler
    #: Parameter name -> JSON type name (``string``/``integer``/...).
    parameters: Mapping[str, str]
    required_parameters: frozenset[str]

    def permits(self, roles: frozenset[str] | set[str]) -> bool:
        """True when ``roles`` may call this tool at all.

        A tool without ``required_role`` is open to any authenticated principal
        that holds at least one known role; ``admin`` satisfies every explicit
        requirement (ADR-003).
        """
        if self.required_role is None:
            return bool(roles)
        return is_satisfied(roles, self.required_role)

    @property
    def arguments_schema(self) -> dict[str, dict[str, Any]]:
        """Model-facing JSON description of the accepted arguments."""
        return {
            name: {"type": json_type, "required": name in self.required_parameters}
            for name, json_type in self.parameters.items()
        }

    def validate_arguments(self, arguments: Mapping[str, Any] | None) -> dict[str, Any]:
        """Return a clean copy of ``arguments`` or raise :class:`ToolArgumentError`."""
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            raise ToolArgumentError(f"tool {self.name!r} arguments must be an object")
        supplied = dict(arguments)

        unknown = sorted(set(supplied) - set(self.parameters))
        if unknown:
            raise ToolArgumentError(
                f"tool {self.name!r} does not accept argument(s): {', '.join(unknown)}"
            )
        missing = sorted(self.required_parameters - set(supplied))
        if missing:
            raise ToolArgumentError(
                f"tool {self.name!r} requires argument(s): {', '.join(missing)}"
            )

        for name, value in supplied.items():
            expected = self.parameters[name]
            if not _matches_json_type(value, expected):
                raise ToolArgumentError(f"tool {self.name!r} argument {name!r} must be {expected}")
        try:
            json.dumps(supplied, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ToolArgumentError(
                f"tool {self.name!r} arguments must be JSON-serialisable"
            ) from exc
        return supplied

    async def invoke(self, arguments: Mapping[str, Any], context: AgentContext) -> Any:
        """Execute the handler with validated arguments (no guard checks)."""
        try:
            return await self.handler(**arguments, context=context)
        except ToolError:
            raise
        except Exception as exc:
            raise ToolInvocationError(self.name, type(exc).__name__) from exc

    def __repr__(self) -> str:
        return (
            f"ToolDefinition(name={self.name!r}, read_only={self.read_only}, "
            f"required_role={self.required_role!r})"
        )


@dataclass(frozen=True, slots=True)
class ToolExecutionResult:
    """Outcome returned to the caller of a guarded tool call."""

    status: ToolStatus
    tool_name: str
    output: Any = None
    ticket_id: str | None = None
    approval_token: str | None = None
    expires_at: datetime | None = None
    error: str | None = None

    @property
    def executed(self) -> bool:
        return self.status is ToolStatus.EXECUTED

    def to_payload(self) -> dict[str, Any]:
        """JSON-safe representation for ARQ job results and API responses."""
        payload: dict[str, Any] = {
            "status": self.status.value,
            "tool": self.tool_name,
            "output": self.output,
        }
        if self.ticket_id is not None:
            payload["ticket_id"] = self.ticket_id
        if self.approval_token is not None:
            # Capability for the initiating client only; never logged.
            payload["approval_token"] = self.approval_token
        if self.expires_at is not None:
            payload["expires_at"] = self.expires_at.isoformat()
        if self.error is not None:
            payload["error"] = self.error
        return payload


def _matches_json_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    return False


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, ToolDefinition] = {}


def tool_registry() -> Mapping[str, ToolDefinition]:
    """Read-only view of every registered tool."""
    return MappingProxyType(_REGISTRY)


def get_tool(name: str) -> ToolDefinition:
    """Look up one tool or raise :class:`ToolNotFoundError`."""
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise ToolNotFoundError(f"unknown tool: {name!r}") from exc


def list_tools() -> tuple[ToolDefinition, ...]:
    """All tools, ordered by name (stable prompt/tool-list output)."""
    return tuple(_REGISTRY[name] for name in sorted(_REGISTRY))


def available_tools(roles: frozenset[str] | set[str]) -> tuple[ToolDefinition, ...]:
    """Tools the caller may invoke, ordered by name.

    Role-denied tools are filtered out of the model-facing tool list rather than
    rejected at call time (ADR-003).
    """
    return tuple(definition for definition in list_tools() if definition.permits(roles))


def unregister_tool(name: str) -> ToolDefinition | None:
    """Remove a tool from the registry (test and plugin-unload use only)."""
    return _REGISTRY.pop(name, None)


def tool(
    *,
    name: str,
    description: str,
    read_only: bool,
    required_role: str | None = None,
) -> Callable[[ToolHandler], ToolHandler]:
    """Declare and register a guarded tool.

    Read-only tools run immediately when RBAC permits. Mutating tools are
    suspended by the execution guard until a second operator approves them.
    """

    def decorator(handler: ToolHandler) -> ToolHandler:
        definition = _build_definition(
            handler,
            name=name,
            description=description,
            read_only=read_only,
            required_role=required_role,
        )
        _REGISTRY[definition.name] = definition
        handler.__tool_definition__ = definition  # type: ignore[attr-defined]
        logger.debug(
            "Tool registered",
            extra={
                "tool": definition.name,
                "read_only": definition.read_only,
                "required_role": definition.required_role,
            },
        )
        return handler

    return decorator


def _build_definition(
    handler: ToolHandler,
    *,
    name: str,
    description: str,
    read_only: bool,
    required_role: str | None,
) -> ToolDefinition:
    if not _TOOL_NAME_PATTERN.match(name):
        raise ToolDefinitionError(
            f"invalid tool name {name!r}: use 3-64 lowercase letters, digits or underscores"
        )
    if name in _REGISTRY:
        raise ToolDefinitionError(f"tool {name!r} is already registered")
    if not description.strip():
        raise ToolDefinitionError(f"tool {name!r} needs a non-empty description")
    if not read_only and required_role is None:
        raise ToolDefinitionError(f"tool {name!r} is mutating and must declare a required_role")
    if required_role is not None and required_role not in ROLE_NAMES:
        raise ToolDefinitionError(
            f"tool {name!r} declares unknown role {required_role!r}; "
            f"expected one of {sorted(ROLE_NAMES)}"
        )
    if not inspect.iscoroutinefunction(handler):
        raise ToolDefinitionError(f"tool {name!r} handler must be an async function")

    signature = inspect.signature(handler)
    if "context" not in signature.parameters:
        raise ToolDefinitionError(f"tool {name!r} handler must declare a 'context' parameter")

    try:
        hints = get_type_hints(handler)
    except NameError as exc:  # pragma: no cover - import-time annotation mistake
        raise ToolDefinitionError(
            f"tool {name!r} has unresolvable type annotations: {exc}"
        ) from exc

    parameters: dict[str, str] = {}
    required: set[str] = set()
    for parameter_name, parameter in signature.parameters.items():
        if parameter_name == "context":
            if parameter.kind not in (
                inspect.Parameter.KEYWORD_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            ):
                raise ToolDefinitionError(
                    f"tool {name!r}: 'context' must be a normal keyword parameter"
                )
            continue
        if parameter.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            raise ToolDefinitionError(f"tool {name!r}: variadic parameters are not supported")
        if parameter_name not in hints:
            raise ToolDefinitionError(
                f"tool {name!r}: parameter {parameter_name!r} needs a JSON type annotation"
            )
        json_type = _JSON_TYPES.get(hints[parameter_name])
        if json_type is None:
            raise ToolDefinitionError(
                f"tool {name!r}: parameter {parameter_name!r} must be str, int, float or bool"
            )
        parameters[parameter_name] = json_type
        if parameter.default is inspect.Parameter.empty:
            required.add(parameter_name)

    return ToolDefinition(
        name=name,
        description=description.strip(),
        read_only=read_only,
        required_role=required_role,
        handler=handler,
        parameters=MappingProxyType(parameters),
        required_parameters=frozenset(required),
    )


def definitions_for(handlers: Iterable[ToolHandler]) -> tuple[ToolDefinition, ...]:
    """Definitions attached to already-decorated handlers (declaration helpers)."""
    definitions = []
    for handler in handlers:
        definition = getattr(handler, "__tool_definition__", None)
        if not isinstance(definition, ToolDefinition):  # pragma: no cover - misuse
            raise ToolDefinitionError(
                f"{getattr(handler, '__name__', handler)!r} is not decorated with @tool"
            )
        definitions.append(definition)
    return tuple(definitions)
