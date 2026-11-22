"""The stateless MCP surface: Bearer wall, then the SDK transport (ADR-028).

The wall is deliberately outside the SDK: the tokens are Keycloak access tokens
whose issuer, audience and agent-registry checks already live in
:mod:`gateway.auth`, and the SDK's OAuth resource-server machinery is not used
(ADR-028 decision 3). A request is authenticated, the caller is bound to a
request-scoped context variable, and only then does the MCP app see it.

Two refusals happen before dispatch, because the transport would otherwise
accept them:

* the legacy leg — a JSON-RPC request without ``params._meta`` — where the
  ``Mcp-Method``/``Mcp-Name`` comparison against the body is skipped;
* any method other than ``POST``, which a stateless server has nothing to do
  with (no SSE stream to open).
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import Any, Final

from fastapi import HTTPException
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agent.tools.mcp_server import (
    McpCaller,
    build_server,
    new_session_id,
    reset_caller,
    set_caller,
)
from db.session import session_scope
from gateway.auth.agents import authorize_agent, effective_tools
from gateway.auth.oidc import Principal, TokenValidationError, parse_bearer_token
from gateway.auth.rbac import get_mcp_token_validator
from gateway.rate_limit import (
    RateLimitDecision,
    RateLimitUnavailable,
    get_rate_limiter,
    refusal_headers,
)
from settings import get_settings

logger = logging.getLogger(__name__)

MCP_PATH: Final[str] = "/mcp"

#: The JSON-RPC methods this surface serves. Used only for the pre-dispatch
#: envelope check; the SDK owns dispatch itself.
_SERVED_METHODS: Final[tuple[str, ...]] = ("tools/list", "tools/call", "server/discover")

_WWW_AUTHENTICATE: Final[dict[str, str]] = {"WWW-Authenticate": 'Bearer realm="bastion-mcp"'}

#: Buffering ceiling for one POST, matched to the SDK manager's default. The
#: argument ceiling (``tool_max_argument_bytes``) is enforced in the execution
#: state machine; this one bounds what the transport will hold at all, and it
#: is applied after the credential is checked so an anonymous caller cannot
#: make the gateway buffer anything.
_MAX_BODY_BYTES: Final[int] = 4 * 1024 * 1024


class McpBodyTooLarge(Exception):
    """The request declared or produced a body over the transport ceiling."""


class McpRefused(Exception):
    """An authentication or registry refusal, rendered before dispatch."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


async def _read_body(receive: Receive, declared: int | None) -> tuple[list[Message], bytes]:
    """Buffer one bounded HTTP request body so it can be inspected and replayed."""
    if declared is not None and declared > _MAX_BODY_BYTES:
        raise McpBodyTooLarge
    messages: list[Message] = []
    body = bytearray()
    while True:
        message = await receive()
        messages.append(message)
        body += message.get("body", b"")
        if len(body) > _MAX_BODY_BYTES:
            raise McpBodyTooLarge
        if not message.get("more_body", False):
            return messages, bytes(body)


def _replay(messages: list[Message]) -> Receive:
    """A ``receive`` that yields the buffered body, then disconnects."""
    queue = list(messages)

    async def receive() -> Message:
        if queue:
            return queue.pop(0)
        return {"type": "http.disconnect"}

    return receive


def _content_length(scope: Scope) -> int | None:
    """The declared body size, so an oversized POST is refused before reading."""
    raw = Headers(scope=scope).get("content-length")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _legacy_request(body: bytes) -> dict[str, Any] | None:
    """The request's JSON-RPC method when it is served but missing ``_meta``.

    The 2026-07-28 envelope carries the version and client capabilities in
    ``params._meta``; a body without it takes the SDK's pre-2026 leg, where the
    ``Mcp-Method`` header is not compared with the body (ADR-028 decision 4).
    """
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    method = payload.get("method")
    if method not in _SERVED_METHODS:
        return None
    params = payload.get("params")
    if isinstance(params, dict) and "_meta" in params:
        return None
    return payload


async def _json(
    send: Send, status_code: int, payload: dict[str, Any], headers: dict[str, str] | None = None
) -> None:
    await JSONResponse(payload, status_code=status_code, headers=headers)(
        _EMPTY_SCOPE, _noop_receive, send
    )


async def _noop_receive() -> Message:
    return {"type": "http.disconnect"}


_EMPTY_SCOPE: Final[Scope] = {"type": "http", "method": "GET", "path": "/", "headers": []}


async def _authenticate(scope: Scope) -> Principal:
    """Resolve the caller and the request session for one MCP request."""
    headers = Headers(scope=scope)
    header = headers.get("authorization")
    token = parse_bearer_token(header)
    if token is None:
        raise McpRefused(HTTPStatus.UNAUTHORIZED, "missing or malformed bearer token")
    try:
        principal = await get_mcp_token_validator().validate_access_token(token)
    except TokenValidationError as exc:
        logger.info("MCP token rejected", extra={"reason": exc.code})
        raise McpRefused(HTTPStatus.UNAUTHORIZED, "invalid bearer token") from exc
    return principal


async def _caller_for(principal: Principal, session: Any) -> McpCaller:
    agent = None
    if principal.actor_type == "agent":
        try:
            agent = await authorize_agent(session, principal, MCP_PATH)
        except HTTPException as exc:
            # A registry refusal is a 403 with its ledger row already written;
            # translate it here, because the wall runs outside FastAPI's handler.
            raise McpRefused(exc.status_code, str(exc.detail)) from exc
    return McpCaller(
        actor_id=principal.subject,
        tenant_id=principal.tenant_id,
        roles=principal.roles,
        session_id=new_session_id(),
        actor_type=principal.actor_type,
        agent_id=principal.agent_id,
        owner_sub=agent.owner_sub if agent is not None else None,
        allowed_tools=effective_tools(agent) if agent is not None else None,
        rate_limit_subject=agent.budget_key if agent is not None else principal.subject,
        session=session,
    )


class McpSurface:
    """One application's MCP transport, with the wall in front of it."""

    def __init__(self) -> None:
        self._manager = StreamableHTTPSessionManager(
            app=build_server(), stateless=True, json_response=True
        )

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        """Run the session manager for the host app's lifetime.

        Mounting the SDK app would disable its own lifespan; without this entry
        the first request fails (ADR-028 decision 2).
        """
        async with self._manager.run():
            yield

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("method") != "POST":
            await JSONResponse(
                {"error": "the MCP surface answers POST only"},
                status_code=HTTPStatus.METHOD_NOT_ALLOWED,
                headers={"Allow": "POST"},
            )(scope, receive, send)
            return

        try:
            principal = await _authenticate(scope)
        except McpRefused as exc:
            await JSONResponse(
                {"error": exc.message},
                status_code=exc.status_code,
                headers=_WWW_AUTHENTICATE if exc.status_code == HTTPStatus.UNAUTHORIZED else None,
            )(scope, receive, send)
            return

        async with session_scope() as session:
            try:
                caller = await _caller_for(principal, session)
            except McpRefused as exc:
                await JSONResponse({"error": exc.message}, status_code=exc.status_code)(
                    scope, receive, send
                )
                return

            # The registry lookup opened a transaction and checked out one pooled
            # connection. Release it before the caller-paced reads below, so a
            # slow upload cannot pin the pool every database-backed surface
            # shares; the next statement re-acquires one when it needs it.
            await session.commit()

            # Charge the bucket before the body is read (IDEA-109): a refused
            # caller cannot make the gateway buffer anything.
            refusal = await _charge(caller)
            if refusal is not None:
                await refusal(scope, receive, send)
                return

            try:
                messages, body = await _read_body(receive, _content_length(scope))
            except McpBodyTooLarge:
                await JSONResponse(
                    {"error": "request body too large"},
                    status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )(scope, receive, send)
                return

            legacy = _legacy_request(body)
            if legacy is not None:
                await JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": legacy.get("id"),
                        "error": {
                            "code": -32600,
                            "message": (
                                "the 2026-07-28 envelope is required: params._meta must carry "
                                "the protocol version"
                            ),
                        },
                    },
                    status_code=HTTPStatus.OK,
                )(scope, receive, send)
                return

            set_caller(caller)
            try:
                inner = dict(scope)
                inner["path"] = "/"
                inner["root_path"] = ""
                await self._manager.handle_request(inner, _replay(messages), send)
            finally:
                reset_caller()


async def _charge(caller: McpCaller) -> JSONResponse | None:
    """Take one request from the caller's bucket, or say why not (IDEA-109).

    Runs after the registry check and before the body is read, so a suspended
    caller drains no budget and a refused one makes the gateway buffer nothing.
    """
    settings = get_settings()
    if not settings.rate_limit_enabled:
        return None
    try:
        decision: RateLimitDecision = await get_rate_limiter().consume(
            caller.rate_limit_subject,
            "mcp",
            limit=settings.rate_limit_mcp_per_window,
            window_seconds=settings.rate_limit_window_seconds,
        )
    except RateLimitUnavailable:
        return JSONResponse({"error": "rate limiter unavailable"}, status_code=503)
    if decision.allowed:
        return None
    logger.warning(
        "MCP rate limit exceeded",
        extra={
            "subject": caller.actor_id,
            "scope": "mcp",
            "limit": decision.limit,
            "retry_after_seconds": decision.retry_after_seconds,
        },
    )
    return JSONResponse(
        {"error": "rate limit exceeded"},
        status_code=429,
        headers=refusal_headers(decision),
    )


class McpMiddleware:
    """Route exactly ``/mcp`` to the surface, everything else to the app."""

    def __init__(self, app: ASGIApp, surface: McpSurface) -> None:
        self.app = app
        self.surface = surface

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path") == MCP_PATH:
            await self.surface(scope, receive, send)
            return
        await self.app(scope, receive, send)


def install(app: Any) -> McpSurface:
    """Attach the surface to a FastAPI app and return it for the lifespan."""
    surface = McpSurface()
    app.add_middleware(McpMiddleware, surface=surface)
    return surface
