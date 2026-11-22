"""The stateless MCP surface (ADR-028, IDEA-107).

Driven over HTTP against the real app, with a stub token validator and the
test database: the claim under test is the wire contract (envelope, headers,
auth) and that every tool call goes through the one guarded execution path,
not that the classifier or the model work.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import gateway.routers.mcp as mcp_router
from agent.tools import AgentContext, tool, unregister_tool
from db.models import PendingApproval
from gateway.auth.oidc import Principal, TokenValidationError
from gateway.auth.rbac import get_mcp_token_validator
from gateway.main import create_app
from settings import get_settings
from tests.conftest import requires_database

pytestmark = [pytest.mark.integration, requires_database]

META: dict[str, Any] = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "pytest", "version": "0"},
}

ALICE = Principal(
    subject="alice-sub", tenant_id="acme", username="alice", roles=frozenset({"operator"})
)


class StubValidator:
    """Accepts ``mcp-token``; anything else is the gateway audience and refused."""

    audience = "bastion-mcp"

    async def validate_access_token(self, token: str) -> Principal:
        if token != "mcp-token":
            raise TokenValidationError("invalid_audience", "token is not for this surface")
        return ALICE


@dataclass
class Harness:
    client: httpx.AsyncClient
    engine: AsyncEngine
    requests: list[dict[str, Any]] = field(default_factory=list)

    def headers(self, method: str, name: str | None = None) -> dict[str, str]:
        headers = {
            "authorization": "Bearer mcp-token",
            "content-type": "application/json",
            "accept": "application/json",
            "mcp-protocol-version": "2026-07-28",
            "mcp-method": method,
        }
        if name is not None:
            headers["mcp-name"] = name
        return headers

    async def list_tools(self) -> httpx.Response:
        return await self.client.post(
            "/mcp",
            headers=self.headers("tools/list"),
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": META}},
        )

    async def call(self, name: str, arguments: dict[str, Any], *, ident: int = 2) -> httpx.Response:
        return await self.client.post(
            "/mcp",
            headers=self.headers("tools/call", name),
            json={
                "jsonrpc": "2.0",
                "id": ident,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments, "_meta": META},
            },
        )


@pytest_asyncio.fixture
async def mcp(db_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Harness]:
    app = create_app()
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    @asynccontextmanager
    async def scope() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
            except BaseException:
                await session.rollback()
                raise
            await session.commit()

    monkeypatch.setattr(mcp_router, "get_mcp_token_validator", StubValidator)
    monkeypatch.setattr(mcp_router, "session_scope", scope)

    # The manager's task group must be entered and exited by one task, so the
    # lifespan runs in its own task and the fixture only signals it.
    ready = asyncio.Event()
    stop = asyncio.Event()

    async def run_lifespan() -> None:
        async with app.state.mcp_surface.lifespan():
            ready.set()
            await stop.wait()

    lifespan = asyncio.create_task(run_lifespan())
    await ready.wait()
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield Harness(client=client, engine=db_engine)
    finally:
        stop.set()
        await lifespan


async def _ticket_count(harness: Harness) -> int:
    factory = async_sessionmaker(harness.engine, expire_on_commit=False)
    async with factory() as session:
        return (
            await session.execute(select(func.count()).select_from(PendingApproval))
        ).scalar_one()


# ---------------------------------------------------------------------------
# The wire contract
# ---------------------------------------------------------------------------


async def test_tools_list_serves_the_approved_catalog_text(mcp: Harness) -> None:
    response = await mcp.list_tools()

    assert response.status_code == 200
    tools = {tool["name"]: tool for tool in response.json()["result"]["tools"]}
    assert set(tools) == {"read_file", "read_system_status", "execute_file_write"}
    listed = tools["read_file"]
    assert listed["description"].startswith("Read a UTF-8 text file")
    assert listed["inputSchema"]["required"] == ["path"]
    # The digests the approval record pins travel with the tool (IDEA-107).
    assert listed["_meta"]["server"] == "builtin"
    assert len(listed["_meta"]["description_hash"]) == 64
    assert len(listed["_meta"]["input_schema_hash"]) == 64


async def test_no_session_header_and_no_initialize_handshake(mcp: Harness) -> None:
    response = await mcp.list_tools()

    assert "mcp-session-id" not in response.headers
    assert "result" in response.json()


async def test_a_bare_legacy_envelope_is_refused(mcp: Harness) -> None:
    """Without ``params._meta`` the SDK would take the leg that skips the header check."""
    response = await mcp.client.post(
        "/mcp",
        headers=mcp.headers("tools/list"),
        json={"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}},
    )

    error = response.json()["error"]
    assert error["code"] == -32600
    assert "params._meta" in error["message"]


async def test_a_header_that_disagrees_with_the_body_is_refused_before_dispatch(
    mcp: Harness,
) -> None:
    response = await mcp.client.post(
        "/mcp",
        headers=mcp.headers("tools/list", "read_file"),
        json={
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "x"}, "_meta": META},
        },
    )

    assert response.json()["error"]["code"] == -32020
    assert await _ticket_count(mcp) == 0


async def test_only_post_is_answered(mcp: Harness) -> None:
    response = await mcp.client.get("/mcp")

    assert response.status_code == 405
    assert response.headers["allow"] == "POST"


async def test_resources_and_prompts_are_not_served(mcp: Harness) -> None:
    response = await mcp.client.post(
        "/mcp",
        headers=mcp.headers("resources/list"),
        json={"jsonrpc": "2.0", "id": 11, "method": "resources/list", "params": {"_meta": META}},
    )

    assert response.json()["error"]["code"] == -32601


# ---------------------------------------------------------------------------
# Authentication: one audience per surface
# ---------------------------------------------------------------------------


async def test_a_gateway_audience_token_is_refused(mcp: Harness) -> None:
    response = await mcp.client.post(
        "/mcp",
        headers={**mcp.headers("tools/list"), "authorization": "Bearer bastion-gateway"},
        json={"jsonrpc": "2.0", "id": 12, "method": "tools/list", "params": {"_meta": META}},
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


async def test_no_credential_is_refused(mcp: Harness) -> None:
    headers = {k: v for k, v in mcp.headers("tools/list").items() if k != "authorization"}
    response = await mcp.client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 13, "method": "tools/list", "params": {"_meta": META}},
    )

    assert response.status_code == 401


def test_the_mcp_validator_uses_the_mcp_audience() -> None:
    settings = get_settings()

    assert settings.mcp_audience != settings.keycloak_audience
    assert get_mcp_token_validator().audience == settings.mcp_audience


# ---------------------------------------------------------------------------
# The gates
# ---------------------------------------------------------------------------


async def test_a_registered_tool_outside_the_catalog_is_invisible(mcp: Harness) -> None:
    """The catalog is an allow-list: importing a tool does not expose it."""

    @tool(name="rogue_tool", description="registered but never approved", read_only=True)
    async def rogue_tool(context: AgentContext) -> dict[str, str]:
        return {"ran": "unexpected"}

    try:
        tools = (await mcp.list_tools()).json()["result"]["tools"]
        assert "rogue_tool" not in {entry["name"] for entry in tools}
        assert (await mcp.call("rogue_tool", {})).json()["error"]["code"] == -32003
    finally:
        unregister_tool("rogue_tool")


async def test_an_unapproved_name_is_32003_without_a_ticket(mcp: Harness) -> None:
    response = await mcp.call("drop_database", {})

    assert response.json()["error"]["code"] == -32003
    assert await _ticket_count(mcp) == 0


async def test_a_read_only_tool_executes(mcp: Harness) -> None:
    response = await mcp.call("read_system_status", {})

    result = json.loads(response.json()["result"]["content"][0]["text"])
    assert result["status"] == "executed"
    assert result["tool"] == "read_system_status"


async def test_a_mutating_tool_suspends_for_four_eyes(mcp: Harness) -> None:
    response = await mcp.call("execute_file_write", {"path": "note.txt", "content": "hi"})

    result = json.loads(response.json()["result"]["content"][0]["text"])
    assert result["status"] == "approval_pending"
    assert result["ticket_id"]
    assert result["approval_token"]
    assert await _ticket_count(mcp) == 1
