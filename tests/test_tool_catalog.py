"""ADR-009 Gate 1: the versioned tool allow-list (parsing and filtering)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agent.tools import (
    TOOL_NOT_IN_CATALOG_CODE,
    AgentContext,
    CatalogTool,
    ToolCatalogDriftError,
    ToolCatalogUnavailableError,
    ToolNotInCatalogError,
    available_tools,
    get_tool_catalog,
    list_tools,
    load_catalog,
    override_tool_catalog,
    reset_tool_catalog_cache,
    tool,
    unregister_tool,
    verify_registry,
)
from settings import reset_settings_cache


def entry(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "description": "fixture",
        "read_only": True,
        "required_role": None,
        "require_approval": False,
        "arguments": {},
    }
    base.update(overrides)
    return base


def write_catalog(path: Path, tools: dict[str, Any], *, version: Any = "v1") -> Path:
    path.write_text(json.dumps({"version": version, "tools": tools}), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# The checked-in catalog
# ---------------------------------------------------------------------------


def test_checked_in_catalog_matches_the_registry() -> None:
    catalog = get_tool_catalog()

    assert catalog.version == "v1"
    assert verify_registry(catalog) is catalog
    assert {definition.name for definition in list_tools()} <= catalog.names()
    assert catalog.tools["execute_file_write"].require_approval is True
    assert catalog.tools["read_file"].require_approval is False
    assert catalog.tools["read_file"].required_role is None


def test_unknown_and_drifted_tools_raise_catalog_errors() -> None:
    catalog = get_tool_catalog()

    with pytest.raises(ToolNotInCatalogError) as info:
        catalog.authorize(SimpleNamespace(name="not_approved"))
    assert info.value.code == TOOL_NOT_IN_CATALOG_CODE == -32003

    drifted = catalog.with_tools(
        {
            "read_file": CatalogTool(
                name="read_file",
                description="a different description",
                read_only=True,
                required_role=None,
                require_approval=False,
                arguments={"path": {"type": "string", "required": True}},
            )
        }
    )
    with pytest.raises(ToolCatalogDriftError, match="description"):
        drifted.authorize(next(d for d in list_tools() if d.name == "read_file"))


def test_registry_drift_is_reported_for_startup() -> None:
    catalog = get_tool_catalog()

    with pytest.raises(ToolCatalogDriftError, match="unapproved"):
        verify_registry(catalog.without("read_file"))
    with pytest.raises(ToolCatalogDriftError, match="stale allow-list"):
        stale = catalog.with_tools(
            {
                "read_file_old": CatalogTool(
                    name="read_file_old",
                    description="gone",
                    read_only=True,
                    required_role=None,
                    require_approval=False,
                    arguments={},
                )
            }
        )
        verify_registry(stale)


# ---------------------------------------------------------------------------
# Fail-closed loading
# ---------------------------------------------------------------------------


def test_mutating_tool_cannot_waive_approval(tmp_path: Path) -> None:
    path = write_catalog(
        tmp_path / "v1.json",
        {"write_it": entry(read_only=False, required_role="operator", require_approval=False)},
    )

    with pytest.raises(ToolCatalogUnavailableError, match="cannot waive"):
        load_catalog(path)


def test_forced_approval_needs_a_required_role(tmp_path: Path) -> None:
    path = write_catalog(
        tmp_path / "v1.json",
        {"read_it": entry(require_approval=True, required_role=None)},
    )

    with pytest.raises(ToolCatalogUnavailableError, match="no required_role"):
        load_catalog(path)


def test_unknown_fields_and_roles_are_rejected(tmp_path: Path) -> None:
    extra = write_catalog(tmp_path / "v1.json", {"read_it": entry(unexpected=True)})
    with pytest.raises(ToolCatalogUnavailableError, match="unknown field"):
        load_catalog(extra)

    bad_role = write_catalog(tmp_path / "v1.json", {"read_it": entry(required_role="root")})
    with pytest.raises(ToolCatalogUnavailableError, match="required_role"):
        load_catalog(bad_role)

    bad_version = write_catalog(tmp_path / "v1.json", {"read_it": entry()}, version="1")
    with pytest.raises(ToolCatalogUnavailableError, match="version"):
        load_catalog(bad_version)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "v1.json"
    path.write_text(
        '{"version": "v1", "tools": {'
        '"read_it": {"description": "a", "read_only": true, "required_role": null, '
        '"require_approval": false, "arguments": {}}, '
        '"read_it": {"description": "b", "read_only": true, "required_role": null, '
        '"require_approval": false, "arguments": {}}}}',
        encoding="utf-8",
    )

    with pytest.raises(ToolCatalogUnavailableError, match="duplicate key"):
        load_catalog(path)


def test_missing_catalog_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ToolCatalogUnavailableError, match="cannot read"):
        load_catalog(tmp_path / "v1.json")


def test_missing_catalog_exposes_no_tools(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TOOL_CATALOG_PATH", str(tmp_path / "absent.json"))
    reset_settings_cache()
    reset_tool_catalog_cache()
    try:
        with pytest.raises(ToolCatalogUnavailableError):
            get_tool_catalog()
        assert not available_tools({"admin"})
    finally:
        reset_settings_cache()
        reset_tool_catalog_cache()


# ---------------------------------------------------------------------------
# Model-facing filtering
# ---------------------------------------------------------------------------


def test_available_tools_hides_tools_absent_from_the_catalog() -> None:
    @tool(
        name="test_unlisted_tool",
        description="registered in code, never approved",
        read_only=True,
    )
    async def unlisted(context: AgentContext) -> None: ...

    try:
        names = {definition.name for definition in available_tools({"operator"})}
        assert "test_unlisted_tool" not in names
        assert {"read_file", "read_system_status", "execute_file_write"} <= names

        approved = CatalogTool(
            name="test_unlisted_tool",
            description="registered in code, never approved",
            read_only=True,
            required_role=None,
            require_approval=False,
            arguments={},
        )
        with override_tool_catalog(extra={approved.name: approved}):
            names = {definition.name for definition in available_tools({"operator"})}
        assert "test_unlisted_tool" in names
    finally:
        unregister_tool("test_unlisted_tool")


def test_forced_approval_is_allowed_when_a_role_gates_the_tool(tmp_path: Path) -> None:
    path = write_catalog(
        tmp_path / "v1.json",
        {
            "read_it": entry(
                required_role="operator",
                require_approval=True,
            )
        },
    )

    catalog = load_catalog(path)
    assert catalog.tools["read_it"].require_approval is True
    assert catalog.tools["read_it"].required_role == "operator"


def test_catalog_cannot_change_the_registry_role() -> None:
    """The catalog may only tighten approval, never grant a different role."""
    catalog = get_tool_catalog()
    changed = catalog.with_tools(
        {
            "read_file": CatalogTool(
                name="read_file",
                description=catalog.tools["read_file"].description,
                read_only=True,
                required_role="operator",
                require_approval=True,
                arguments=dict(catalog.tools["read_file"].arguments),
            )
        }
    )

    with pytest.raises(ToolCatalogDriftError, match="required_role"):
        changed.authorize(next(d for d in list_tools() if d.name == "read_file"))


def test_override_is_scoped_and_restored() -> None:
    original = get_tool_catalog()

    with override_tool_catalog(original.without("read_file")):
        assert "read_file" not in get_tool_catalog().names()

    assert "read_file" in get_tool_catalog().names()
