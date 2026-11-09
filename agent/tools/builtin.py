"""Built-in guarded tools (HANDOVER_SPEC §3.2).

The file tools are confined to ``TOOL_WORKSPACE_ROOT``: absolute paths,
``..`` traversal and symlinks that resolve outside the root are rejected before
any IO happens. Writes are atomic (temp file + ``os.replace``) and capped by
``TOOL_MAX_WRITE_BYTES``; reads are capped by ``TOOL_MAX_READ_BYTES``.

Blocking filesystem work runs in a worker thread (``anyio.to_thread``) so a
tool call cannot stall the event loop. Nothing here imports the database or the
network, so importing the tool module cannot fail open. Mutating vs. read-only
policy is declared in the ``@tool`` attributes, not inside the handler.
"""

from __future__ import annotations

import hashlib
import os
import platform
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from anyio import to_thread

from agent.tools.decorator import AgentContext, ToolError, tool
from settings import get_settings

_WORKSPACE_MODE = 0o700
_FILE_MODE = 0o600


class WorkspaceViolation(ToolError):
    """The requested path is outside the tool workspace or otherwise unsafe."""


def _workspace_root() -> Path:
    """Return the resolved workspace root, creating it with owner-only access."""
    settings = get_settings()
    root = Path(settings.tool_workspace_root).expanduser()
    try:
        root.mkdir(parents=True, exist_ok=True, mode=_WORKSPACE_MODE)
    except OSError as exc:
        raise WorkspaceViolation("the tool workspace is not available") from exc
    return root.resolve()


def resolve_workspace_path(raw_path: str) -> Path:
    """Resolve ``raw_path`` inside the workspace or raise :class:`WorkspaceViolation`."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise WorkspaceViolation("path must be a non-empty string")
    candidate = Path(raw_path)
    if candidate.is_absolute():
        raise WorkspaceViolation("absolute paths are not allowed")
    root = _workspace_root()
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root):
        raise WorkspaceViolation("path escapes the tool workspace")
    return resolved


def _display_path(path: Path) -> str:
    """Workspace-relative POSIX path for results (never an absolute host path)."""
    return path.relative_to(_workspace_root()).as_posix()


@tool(
    name="read_system_status",
    description=(
        "Read-only host and runtime status: platform, Python version, UTC time, "
        "workspace root and process id. Safe to call without approval."
    ),
    read_only=True,
)
async def read_system_status(context: AgentContext) -> dict[str, Any]:
    """Return non-sensitive runtime status for the calling principal."""
    return await to_thread.run_sync(_status_sync, context.actor_id)


@tool(
    name="read_file",
    description=(
        "Read a UTF-8 text file from the tool workspace. Paths are relative to the "
        "workspace root; traversal outside it is rejected. Read-only."
    ),
    read_only=True,
)
async def read_file(path: str, context: AgentContext) -> dict[str, Any]:
    """Read a workspace file, capped at ``TOOL_MAX_READ_BYTES``."""
    return await to_thread.run_sync(_read_file_sync, path)


@tool(
    name="execute_file_write",
    description=(
        "Write UTF-8 text to a file in the tool workspace, creating parent "
        "directories as needed. Mutating: suspends until a second operator approves."
    ),
    read_only=False,
    required_role="operator",
)
async def execute_file_write(path: str, content: str, context: AgentContext) -> dict[str, Any]:
    """Atomically write ``content`` to ``path`` inside the workspace."""
    return await to_thread.run_sync(_write_file_sync, path, content, context.actor_id)


# ---------------------------------------------------------------------------
# Blocking implementations (run in a thread)
# ---------------------------------------------------------------------------


def _status_sync(actor_id: str) -> dict[str, Any]:
    root = _workspace_root()
    return {
        "requested_by": actor_id,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "utc_time": datetime.now(UTC).isoformat(),
        "workspace_root": str(root),
        "pid": os.getpid(),
    }


def _read_file_sync(path: str) -> dict[str, Any]:
    settings = get_settings()
    target = resolve_workspace_path(path)
    if not target.exists():
        raise WorkspaceViolation("file does not exist")
    if not target.is_file():
        raise WorkspaceViolation("path is not a regular file")

    size = target.stat().st_size
    if size > settings.tool_max_read_bytes:
        raise WorkspaceViolation(f"file exceeds the {settings.tool_max_read_bytes}-byte read limit")
    data = target.read_bytes()
    if len(data) > settings.tool_max_read_bytes:
        # The file grew between stat and read; refuse rather than truncate.
        raise WorkspaceViolation(f"file exceeds the {settings.tool_max_read_bytes}-byte read limit")
    return {
        "path": _display_path(target),
        "bytes": len(data),
        "content": data.decode("utf-8", errors="replace"),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _write_file_sync(path: str, content: str, actor_id: str) -> dict[str, Any]:
    settings = get_settings()
    encoded = content.encode("utf-8")
    if len(encoded) > settings.tool_max_write_bytes:
        raise WorkspaceViolation(
            f"content exceeds the {settings.tool_max_write_bytes}-byte write limit"
        )

    target = resolve_workspace_path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True, mode=_WORKSPACE_MODE)
    except OSError as exc:
        raise WorkspaceViolation("could not create the destination directory") from exc

    # Re-resolve after creating the parent: a symlink introduced between the
    # first check and the write must not be able to redirect us outside the root.
    root = _workspace_root()
    final_target = (target.parent.resolve() / target.name).resolve()
    if not final_target.is_relative_to(root):
        raise WorkspaceViolation("path escapes the tool workspace")

    try:
        descriptor, temp_name = tempfile.mkstemp(prefix=".bastion-write-", dir=final_target.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, _FILE_MODE)
            os.replace(temp_name, final_target)
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise WorkspaceViolation("the file could not be written") from exc

    return {
        "path": _display_path(final_target),
        "bytes_written": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "written_by": actor_id,
    }
