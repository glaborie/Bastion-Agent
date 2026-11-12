"""Authenticated WebSocket stream for the approval queue (ADR-007 decision 3).

The browser presents the same opaque session cookie as every dashboard route,
plus the session's CSRF token in the ``bastion.csrf.<token>`` WebSocket
subprotocol (query parameter and ``X-CSRF-Token`` remain accepted for non-browser
clients). The handshake is rejected when either is missing, when the Origin is
foreign, or when the principal is not an operator/admin. The socket is read-only:
it never accepts a decision, it only tells the page that the queue changed.

Each connection subscribes to its own tenant's Redis channel, so one operator
can never observe another tenant's ticket ids even though every gateway replica
shares the same Redis instance (ADR-015). The page refreshes the queue through
``GET /api/approvals`` after an event, which re-applies the tenant-scoped query.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, Depends, WebSocket
from redis.asyncio import Redis
from starlette.websockets import WebSocketDisconnect

from agent.approvals_events import subscribe_approval_events
from db.redis import get_redis
from gateway.auth.rbac import get_session_manager, is_same_origin
from gateway.auth.roles import any_satisfied
from gateway.auth.session import SessionManager
from settings import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["approvals"])

_WS_UNAUTHORIZED = 4401
_WS_FORBIDDEN = 4403
_CSRF_SUBPROTOCOL_PREFIX = "bastion.csrf."


def get_approval_events_redis() -> Redis:
    """Shared Redis client for the pub/sub bus (overridable in tests)."""
    settings = get_settings()
    return get_redis(settings.redis_url, max_connections=settings.redis_max_connections)


def _csrf_carrier(websocket: WebSocket) -> str | None:
    """Return the ``bastion.csrf.<token>`` subprotocol the client offered.

    A browser cannot set custom headers on a WebSocket, so the token rides in a
    subprotocol rather than the URL; that keeps it out of access logs while still
    failing closed when absent. Only this carrier counts: an unrelated protocol
    (``graphql-ws``, a vendor extension) is never selected.
    """
    offered = websocket.headers.get("sec-websocket-protocol", "")
    for raw in offered.split(","):
        protocol = raw.strip()
        if protocol.startswith(_CSRF_SUBPROTOCOL_PREFIX):
            return protocol
    return None


def _csrf_from_subprotocol(websocket: WebSocket) -> str | None:
    """Read the token from the carrier subprotocol, if the client sent one."""
    carrier = _csrf_carrier(websocket)
    return carrier.removeprefix(_CSRF_SUBPROTOCOL_PREFIX) if carrier else None


async def _reject(websocket: WebSocket, code: int, reason: str) -> None:
    logger.info("Approval WebSocket rejected", extra={"reason": reason})
    await websocket.close(code=code)


async def _authenticate(
    websocket: WebSocket,
    sessions: SessionManager,
) -> tuple[str, str] | None:
    """Return ``(tenant_id, session_id)`` for an authorised operator."""
    settings = get_settings()
    session_id = websocket.cookies.get(settings.session_cookie_name)
    if not session_id:
        await _reject(websocket, _WS_UNAUTHORIZED, "missing_session")
        return None
    record = await sessions.resolve(session_id)
    if record is None:
        await _reject(websocket, _WS_UNAUTHORIZED, "expired_session")
        return None

    principal = record.principal
    if not any_satisfied(principal.roles, ("operator", "admin")):
        await _reject(websocket, _WS_FORBIDDEN, "insufficient_role")
        return None

    presented = (
        _csrf_from_subprotocol(websocket)
        or websocket.query_params.get("csrf_token")
        or websocket.headers.get("x-csrf-token")
    )
    if not presented or not hmac.compare_digest(presented, record.csrf_token):
        await _reject(websocket, _WS_FORBIDDEN, "csrf")
        return None

    scheme = "https" if websocket.url.scheme == "wss" else "http"
    expected_origin = f"{scheme}://{websocket.url.netloc}"
    if not is_same_origin(websocket.headers.get("origin"), expected_origin):
        await _reject(websocket, _WS_FORBIDDEN, "origin")
        return None

    return principal.tenant_id, record.session_id


async def _wait_for_disconnect(websocket: WebSocket) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return


async def _forward_events(
    websocket: WebSocket, events: AsyncGenerator[dict[str, Any], None]
) -> None:
    async for event in events:
        await websocket.send_json(event)


@router.websocket("/ws/approvals")
async def approvals_stream(
    websocket: WebSocket,
    sessions: SessionManager = Depends(get_session_manager),
    redis: Redis = Depends(get_approval_events_redis),
) -> None:
    """Stream approval changes to one authenticated operator."""
    authenticated = await _authenticate(websocket, sessions)
    if authenticated is None:
        return
    tenant_id, _session_id = authenticated

    await websocket.accept(subprotocol=_csrf_carrier(websocket))
    # A refresh hint closes the gap between page render and socket open; the
    # client treats every message as "re-read the queue".
    await websocket.send_json({"type": "connected"})
    await websocket.send_json({"type": "refresh"})

    events = subscribe_approval_events(redis, tenant_id)
    receiver = asyncio.create_task(_wait_for_disconnect(websocket))
    forwarder = asyncio.create_task(_forward_events(websocket, events))
    try:
        done, pending = await asyncio.wait(
            {receiver, forwarder}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in done:
            if (
                not task.cancelled()
                and (exc := task.exception()) is not None
                and not isinstance(exc, WebSocketDisconnect)
            ):
                logger.debug(
                    "Approval WebSocket closed with an error",
                    extra={"error": type(exc).__name__},
                )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    finally:
        receiver.cancel()
        forwarder.cancel()
        await asyncio.gather(receiver, forwarder, return_exceptions=True)
        await events.aclose()
