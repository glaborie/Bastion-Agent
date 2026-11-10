"""ADR-009 Gate 1: the versioned tool allow-list and its runtime enforcement.

``docs/tools/v1.json`` is the approved capability set. A tool may exist in the
``@tool`` registry (because code imported it) and still be invisible and
uninvokable until its entry is in the catalog: the catalog is an allow-list,
never a discovery mechanism.

Three properties keep the gate fail-closed:

* **Parsing is strict.** Duplicate JSON keys, unknown fields, an unknown role, a
  non-boolean flag or a mutating tool that waives approval all make the catalog
  unreadable. An unreadable catalog exposes no tools rather than all of them.
* **Approval can only be tightened.** ``require_approval`` must be true for a
  mutating tool; setting it true on a read-only tool is allowed, but it then
  needs a ``required_role`` so a second operator can actually decide the ticket.
* **Drift is checked, not assumed.** :func:`compare_catalog` is shared by the
  startup gate, the model-facing tool list and ``scripts/validate_tool_catalog``
  so the three cannot disagree about what "approved" means.

The catalog is loaded once per process and cached against the file's mtime and
size; :func:`reset_tool_catalog_cache` clears it for tests.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Protocol

from agent.tools.errors import (
    ToolCatalogDriftError,
    ToolCatalogUnavailableError,
    ToolNotInCatalogError,
)
from gateway.auth.roles import ROLE_NAMES
from settings import get_settings

logger = logging.getLogger(__name__)

#: Top-level fields the catalog writer emits. Anything else is a typo or an
#: unapproved schema change, so it is rejected instead of ignored.
_CATALOG_FIELDS: Final[frozenset[str]] = frozenset({"version", "generated_by", "tools"})
_ENTRY_FIELDS: Final[frozenset[str]] = frozenset(
    {"description", "read_only", "required_role", "require_approval", "arguments"}
)
_JSON_TYPES: Final[frozenset[str]] = frozenset({"string", "integer", "number", "boolean"})


class _DefinitionLike(Protocol):
    """The slice of :class:`agent.tools.decorator.ToolDefinition` gate 1 reads.

    A protocol keeps this module free of a runtime import of the registry, which
    would create a cycle when the registry filters its tool list through here.
    """

    @property
    def name(self) -> str: ...

    @property
    def description(self) -> str: ...

    @property
    def read_only(self) -> bool: ...

    @property
    def required_role(self) -> str | None: ...

    @property
    def arguments_schema(self) -> dict[str, dict[str, Any]]: ...


@dataclass(frozen=True, slots=True)
class CatalogTool:
    """One approved tool exactly as the catalog declares it."""

    name: str
    description: str
    read_only: bool
    required_role: str | None
    require_approval: bool
    arguments: Mapping[str, Mapping[str, Any]]

    def drift(self, definition: _DefinitionLike) -> list[str]:
        """Differences between this entry and the registered definition."""
        problems: list[str] = []
        if self.read_only is not definition.read_only:
            problems.append(
                f"read_only catalog={self.read_only!r} registry={definition.read_only!r}"
            )
        if self.required_role != definition.required_role:
            problems.append(
                f"required_role catalog={self.required_role!r} "
                f"registry={definition.required_role!r}"
            )
        if self.description != definition.description:
            problems.append("description differs from the registry")
        if dict(self.arguments) != definition.arguments_schema:
            problems.append("arguments differ from the registry")
        return problems


@dataclass(frozen=True, slots=True)
class ToolCatalog:
    """An immutable, versioned set of approved tools."""

    version: str
    source: str
    tools: Mapping[str, CatalogTool]

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self.tools

    def names(self) -> frozenset[str]:
        """Every approved tool name."""
        return frozenset(self.tools)

    def authorize(self, definition: _DefinitionLike) -> CatalogTool:
        """Return the entry for ``definition`` or raise a Gate 1 error."""
        entry = self.tools.get(definition.name)
        if entry is None:
            raise ToolNotInCatalogError(definition.name)
        problems = entry.drift(definition)
        if problems:
            raise ToolCatalogDriftError(f"tool {definition.name!r}: " + "; ".join(problems))
        return entry

    def with_tools(self, extra: Mapping[str, CatalogTool]) -> ToolCatalog:
        """Copy with ``extra`` merged in (test/plugin use only)."""
        merged = dict(self.tools)
        merged.update(extra)
        return replace(self, tools=MappingProxyType(merged))

    def without(self, *names: str) -> ToolCatalog:
        """Copy with ``names`` removed (test use only)."""
        excluded = set(names)
        return replace(
            self,
            tools=MappingProxyType(
                {name: entry for name, entry in self.tools.items() if name not in excluded}
            ),
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ToolCatalogUnavailableError(f"duplicate key {key!r} in the tool catalog")
        result[key] = value
    return result


def _parse_arguments(tool_name: str, raw: object) -> Mapping[str, Mapping[str, Any]]:
    if not isinstance(raw, dict):
        raise ToolCatalogUnavailableError(f"tool {tool_name!r}: arguments must be an object")
    parsed: dict[str, Mapping[str, Any]] = {}
    for argument_name, spec in raw.items():
        if not isinstance(argument_name, str) or not argument_name:
            raise ToolCatalogUnavailableError(f"tool {tool_name!r}: invalid argument name")
        if not isinstance(spec, dict):
            raise ToolCatalogUnavailableError(
                f"tool {tool_name!r} argument {argument_name!r} must be an object"
            )
        if set(spec) != {"type", "required"}:
            raise ToolCatalogUnavailableError(
                f"tool {tool_name!r} argument {argument_name!r} must declare exactly "
                "'type' and 'required'"
            )
        if spec["type"] not in _JSON_TYPES:
            raise ToolCatalogUnavailableError(
                f"tool {tool_name!r} argument {argument_name!r} has unknown type {spec['type']!r}"
            )
        if not isinstance(spec["required"], bool):
            raise ToolCatalogUnavailableError(
                f"tool {tool_name!r} argument {argument_name!r} 'required' must be boolean"
            )
        parsed[argument_name] = {"type": spec["type"], "required": spec["required"]}
    return MappingProxyType(parsed)


def _parse_entry(name: object, raw: object) -> CatalogTool:
    if not isinstance(name, str) or not name.strip():
        raise ToolCatalogUnavailableError(f"invalid tool name in the catalog: {name!r}")
    if not isinstance(raw, dict):
        raise ToolCatalogUnavailableError(f"tool {name!r}: entry must be an object")
    unknown = sorted(set(raw) - _ENTRY_FIELDS)
    missing = sorted(_ENTRY_FIELDS - set(raw))
    if unknown:
        raise ToolCatalogUnavailableError(f"tool {name!r}: unknown field(s) {', '.join(unknown)}")
    if missing:
        raise ToolCatalogUnavailableError(f"tool {name!r}: missing field(s) {', '.join(missing)}")

    description = raw["description"]
    if not isinstance(description, str) or not description.strip():
        raise ToolCatalogUnavailableError(f"tool {name!r}: description must be a non-empty string")
    read_only = raw["read_only"]
    require_approval = raw["require_approval"]
    if not isinstance(read_only, bool):
        raise ToolCatalogUnavailableError(f"tool {name!r}: read_only must be boolean")
    if not isinstance(require_approval, bool):
        raise ToolCatalogUnavailableError(f"tool {name!r}: require_approval must be boolean")

    required_role = raw["required_role"]
    if required_role is not None and (
        not isinstance(required_role, str) or required_role not in ROLE_NAMES
    ):
        raise ToolCatalogUnavailableError(
            f"tool {name!r}: required_role must be null or one of {sorted(ROLE_NAMES)}"
        )
    if not read_only and not require_approval:
        raise ToolCatalogUnavailableError(
            f"tool {name!r} is mutating and cannot waive four-eyes approval"
        )
    if require_approval and required_role is None:
        raise ToolCatalogUnavailableError(
            f"tool {name!r} requires approval but declares no required_role"
        )

    return CatalogTool(
        name=name,
        description=description.strip(),
        read_only=read_only,
        required_role=required_role,
        require_approval=require_approval,
        arguments=_parse_arguments(name, raw["arguments"]),
    )


def load_catalog(path: Path) -> ToolCatalog:
    """Parse and validate one catalog document."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ToolCatalogUnavailableError(f"cannot read tool catalog {path}: {exc}") from exc
    try:
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ToolCatalogUnavailableError(f"tool catalog {path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ToolCatalogUnavailableError(f"tool catalog {path} must contain a JSON object")

    unknown = sorted(set(payload) - _CATALOG_FIELDS)
    if unknown:
        raise ToolCatalogUnavailableError(
            f"tool catalog {path} has unknown field(s): {', '.join(unknown)}"
        )
    version = payload.get("version")
    if not isinstance(version, str) or not version.startswith("v") or not version[1:].isdigit():
        raise ToolCatalogUnavailableError(f"tool catalog {path} must declare a version like 'v1'")
    generated_by = payload.get("generated_by")
    if generated_by is not None and not isinstance(generated_by, str):
        raise ToolCatalogUnavailableError(f"tool catalog {path}: generated_by must be a string")
    raw_tools = payload.get("tools")
    if not isinstance(raw_tools, dict):
        raise ToolCatalogUnavailableError(f"tool catalog {path} needs a 'tools' object")

    tools = {name: _parse_entry(name, entry) for name, entry in sorted(raw_tools.items())}
    return ToolCatalog(version=version, source=str(path), tools=MappingProxyType(tools))


@lru_cache(maxsize=8)
def _load_cached(path: str, mtime_ns: int, size: int) -> ToolCatalog:
    # mtime_ns/size are cache-key material, not inputs to parsing.
    del mtime_ns, size
    return load_catalog(Path(path))


#: Test-only override installed by :func:`override_tool_catalog`.
_OVERRIDE: ToolCatalog | None = None


def get_tool_catalog() -> ToolCatalog:
    """The process catalog, or a test override.

    Raises :class:`ToolCatalogUnavailableError` when the file is missing or
    invalid; callers that expose tools must translate that into "no tools".
    """
    if _OVERRIDE is not None:
        return _OVERRIDE
    path = Path(get_settings().tool_catalog_path).expanduser()
    try:
        stat = path.stat()
    except OSError as exc:
        raise ToolCatalogUnavailableError(f"tool catalog not readable at {path}: {exc}") from exc
    return _load_cached(str(path.resolve()), stat.st_mtime_ns, stat.st_size)


def reset_tool_catalog_cache() -> None:
    """Drop the parsed catalog cache (tests and ``--reload`` use only)."""
    _load_cached.cache_clear()


@contextmanager
def override_tool_catalog(
    catalog: ToolCatalog | None = None,
    *,
    extra: Mapping[str, CatalogTool] | None = None,
) -> Iterator[ToolCatalog]:
    """Temporarily replace the process catalog (tests only)."""
    global _OVERRIDE  # pylint: disable=global-statement
    base = catalog if catalog is not None else get_tool_catalog()
    if extra:
        base = base.with_tools(extra)
    previous = _OVERRIDE
    _OVERRIDE = base
    try:
        yield base
    finally:
        _OVERRIDE = previous


def compare_catalog(catalog: ToolCatalog, definitions: Iterable[_DefinitionLike]) -> list[str]:
    """Every way the registry and the catalog disagree (empty means in sync)."""
    registered = {definition.name: definition for definition in definitions}
    problems: list[str] = []
    for name in sorted(set(registered) - set(catalog.tools)):
        problems.append(f"registered tool {name!r} is not in the catalog (unapproved)")
    for name in sorted(set(catalog.tools) - set(registered)):
        problems.append(f"catalog tool {name!r} is no longer registered (stale allow-list)")
    for name in sorted(set(registered) & set(catalog.tools)):
        for problem in catalog.tools[name].drift(registered[name]):
            problems.append(f"{name}.{problem}")
    return problems
