"""Declarative tool guard, RBAC and workspace confinement (HANDOVER_SPEC §3.2)."""

from __future__ import annotations

import pytest

from agent.tools.builtin import (
    WorkspaceViolation,
    execute_file_write,
    read_file,
    read_system_status,
    resolve_workspace_path,
)
from agent.tools.decorator import (
    AgentContext,
    ToolArgumentError,
    ToolDefinitionError,
    ToolExecutionResult,
    ToolStatus,
    available_tools,
    get_tool,
    list_tools,
    tool,
)
from settings import reset_settings_cache


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    monkeypatch.setenv("TOOL_WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("TOOL_MAX_READ_BYTES", "64")
    monkeypatch.setenv("TOOL_MAX_WRITE_BYTES", "64")
    reset_settings_cache()
    try:
        yield root
    finally:
        reset_settings_cache()


def context(actor: str = "alice", roles: tuple[str, ...] = ("operator",)) -> AgentContext:
    return AgentContext(
        actor_id=actor, tenant_id="acme", roles=frozenset(roles), session_id="sess-tools"
    )


# ---------------------------------------------------------------------------
# Registry and declarations
# ---------------------------------------------------------------------------


def test_builtin_tools_are_registered_with_their_security_attributes() -> None:
    names = {definition.name for definition in list_tools()}
    assert {"read_system_status", "read_file", "execute_file_write"} <= names

    write = get_tool("execute_file_write")
    assert write.read_only is False
    assert write.required_role == "operator"
    assert write.required_parameters == frozenset({"path", "content"})
    assert write.arguments_schema["path"] == {"type": "string", "required": True}

    status = get_tool("read_system_status")
    assert status.read_only is True
    assert status.required_role is None
    assert status.parameters == {}


def test_available_tools_filters_role_denied_tools() -> None:
    analyst = {definition.name for definition in available_tools({"analyst"})}
    assert {"read_file", "read_system_status"} <= analyst
    assert "execute_file_write" not in analyst

    assert "execute_file_write" in {definition.name for definition in available_tools({"operator"})}
    assert "execute_file_write" in {definition.name for definition in available_tools({"admin"})}
    assert not available_tools(set())


def test_duplicate_tool_name_is_rejected() -> None:
    with pytest.raises(ToolDefinitionError, match="already registered"):

        @tool(name="read_file", description="duplicate", read_only=True)
        async def duplicate_read_file(context: AgentContext) -> None: ...


def test_non_async_handler_is_rejected() -> None:
    with pytest.raises(ToolDefinitionError, match="async"):

        @tool(name="test_sync_handler", description="sync", read_only=True)
        def sync_handler(context: AgentContext) -> None: ...


def test_mutating_tool_must_declare_a_role() -> None:
    with pytest.raises(ToolDefinitionError, match="must declare a required_role"):

        @tool(name="test_mutating_without_role", description="open write", read_only=False)
        async def open_write(context: AgentContext) -> None: ...


def test_unknown_required_role_is_rejected() -> None:
    with pytest.raises(ToolDefinitionError, match="unknown role"):

        @tool(
            name="test_unknown_role",
            description="bad role",
            read_only=True,
            required_role="superuser",
        )
        async def unknown_role(context: AgentContext) -> None: ...


def test_handler_must_declare_context() -> None:
    with pytest.raises(ToolDefinitionError, match="context"):

        @tool(name="test_missing_context", description="no context", read_only=True)
        async def missing_context() -> None: ...


def test_parameters_must_be_annotated() -> None:
    with pytest.raises(ToolDefinitionError, match="JSON type annotation"):

        @tool(name="test_untyped", description="untyped", read_only=True)
        async def untyped(path, context: AgentContext) -> None: ...


def test_unsupported_annotations_are_rejected() -> None:
    with pytest.raises(ToolDefinitionError, match="must be str, int, float or bool"):

        @tool(name="test_listing", description="list arg", read_only=True)
        async def listing(paths: list[str], context: AgentContext) -> None: ...


def test_variadic_parameters_are_rejected() -> None:
    with pytest.raises(ToolDefinitionError, match="variadic"):

        @tool(name="test_variadic", description="variadic", read_only=True)
        async def variadic(*args: str, context: AgentContext) -> None: ...


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


def test_missing_and_unknown_arguments_are_rejected() -> None:
    definition = get_tool("execute_file_write")
    with pytest.raises(ToolArgumentError, match="requires argument"):
        definition.validate_arguments({"path": "a.txt"})
    with pytest.raises(ToolArgumentError, match="does not accept"):
        definition.validate_arguments({"path": "a.txt", "content": "x", "extra": 1})


def test_argument_types_are_enforced() -> None:
    definition = get_tool("execute_file_write")
    with pytest.raises(ToolArgumentError, match="must be string"):
        definition.validate_arguments({"path": 1, "content": "x"})
    with pytest.raises(ToolArgumentError, match="must be string"):
        definition.validate_arguments({"path": True, "content": "x"})


def test_arguments_must_be_an_object() -> None:
    definition = get_tool("execute_file_write")
    with pytest.raises(ToolArgumentError, match="must be an object"):
        definition.validate_arguments(["path", "content"])  # type: ignore[arg-type]


def test_arguments_are_copied_not_aliased() -> None:
    definition = get_tool("execute_file_write")
    supplied = {"path": "a.txt", "content": "x"}
    cleaned = definition.validate_arguments(supplied)
    assert cleaned == supplied
    assert cleaned is not supplied


# ---------------------------------------------------------------------------
# Agent context
# ---------------------------------------------------------------------------


def test_context_normalises_and_drops_unknown_roles() -> None:
    ctx = AgentContext(
        actor_id="  alice  ",
        tenant_id="acme",
        roles=frozenset({"OPERATOR", "offline_access"}),
        session_id="s",
    )
    assert ctx.actor_id == "alice"
    assert ctx.roles == frozenset({"operator"})


def test_context_requires_identity_and_session() -> None:
    with pytest.raises(ValueError, match="actor_id"):
        AgentContext(actor_id="", tenant_id="acme", roles=frozenset({"operator"}), session_id="s")
    with pytest.raises(ValueError, match="session_id"):
        AgentContext(
            actor_id="alice", tenant_id="acme", roles=frozenset({"operator"}), session_id=" "
        )


def test_result_payload_is_json_shaped() -> None:
    result = ToolExecutionResult(
        status=ToolStatus.APPROVAL_PENDING,
        tool_name="execute_file_write",
        ticket_id="t",
        approval_token="v1.token",
    )
    payload = result.to_payload()
    assert payload["status"] == "approval_pending"
    assert payload["ticket_id"] == "t"
    assert payload["approval_token"] == "v1.token"
    assert not result.executed


# ---------------------------------------------------------------------------
# Workspace confinement and built-in handlers
# ---------------------------------------------------------------------------


def test_absolute_and_traversing_paths_are_rejected(workspace) -> None:
    with pytest.raises(WorkspaceViolation, match="absolute"):
        resolve_workspace_path("/etc/passwd")
    with pytest.raises(WorkspaceViolation, match="escapes"):
        resolve_workspace_path("../escape.txt")
    with pytest.raises(WorkspaceViolation, match="non-empty"):
        resolve_workspace_path("  ")


def test_symlink_escape_is_rejected(workspace, tmp_path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    workspace.mkdir(parents=True, exist_ok=True)
    link = workspace / "link.txt"
    link.symlink_to(outside)
    with pytest.raises(WorkspaceViolation, match="escapes"):
        resolve_workspace_path("link.txt")


async def test_write_then_read_round_trip(workspace) -> None:
    ctx = context()
    written = await execute_file_write("nested/report.txt", "hello", ctx)
    assert written["path"] == "nested/report.txt"
    assert written["bytes_written"] == 5
    assert written["written_by"] == "alice"

    read = await read_file("nested/report.txt", ctx)
    assert read["content"] == "hello"
    assert read["bytes"] == 5
    assert read["sha256"] == written["sha256"]


async def test_read_of_a_missing_file_is_refused(workspace) -> None:
    with pytest.raises(WorkspaceViolation, match="does not exist"):
        await read_file("missing.txt", context())


async def test_size_limits_are_enforced(workspace) -> None:
    ctx = context()
    with pytest.raises(WorkspaceViolation, match="write limit"):
        await execute_file_write("big.txt", "x" * 65, ctx)

    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "big.txt").write_text("x" * 65)
    with pytest.raises(WorkspaceViolation, match="read limit"):
        await read_file("big.txt", ctx)


async def test_status_tool_reports_the_workspace(workspace) -> None:
    status = await read_system_status(context())
    assert status["requested_by"] == "alice"
    assert status["workspace_root"] == str(workspace.resolve())
    assert status["python_version"]
