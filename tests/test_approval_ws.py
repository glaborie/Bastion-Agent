"""Approval WebSocket authentication, tenant isolation and fan-out (ADR-007)."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from functools import partial
from typing import Any

import pytest
from fakeredis import FakeAsyncRedis
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from agent.approvals_events import (
    channel_for,
    publish_approval_event,
    subscribe_approval_events,
)
from db.models import AuditEventType, utcnow
from gateway.auth.oidc import Principal
from gateway.auth.rbac import get_session_manager
from gateway.auth.session import SessionRecord
from gateway.routers.approval_ws import get_approval_events_redis, router
from settings import get_settings

ACME_OPERATOR = Principal(
    subject="bob-sub", tenant_id="acme", username="bob", roles=frozenset({"operator"})
)
ACME_READONLY = Principal(
    subject="dave-sub", tenant_id="acme", username="dave", roles=frozenset({"readonly"})
)


def _record(principal: Principal, *, csrf_token: str = "csrf-1") -> SessionRecord:
    now = utcnow()
    return SessionRecord(
        session_id="session-1",
        principal=principal,
        access_token="access-token",
        csrf_token=csrf_token,
        created_at=now,
        access_expires_at=now + timedelta(minutes=5),
        last_seen_at=now,
    )


class StubSessions:
    def __init__(self, record: SessionRecord | None) -> None:
        self.record = record

    async def resolve(self, session_id: str) -> SessionRecord | None:
        return self.record if session_id == "session-1" else None


class FakePubSub:
    def __init__(self, broker: FakeBroker) -> None:
        self._broker = broker
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._channel: str | None = None

    async def subscribe(self, channel: str) -> None:
        self._channel = channel
        self._broker.subscribers.setdefault(channel, set()).add(self)

    async def unsubscribe(self, channel: str) -> None:
        self._broker.subscribers.get(channel, set()).discard(self)

    async def aclose(self) -> None:
        if self._channel:
            await self.unsubscribe(self._channel)

    def deliver(self, message: dict[str, Any]) -> None:
        self._queue.put_nowait(message)

    async def get_message(
        self,
        *,
        ignore_subscribe_messages: bool = True,
        timeout: float = 1.0,  # noqa: ASYNC109 - mirrors redis-py's keyword
    ) -> dict[str, Any] | None:
        del ignore_subscribe_messages
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except TimeoutError:
            return None


class FakeBroker:
    """Minimal async pub/sub surface used by the real event helpers."""

    def __init__(self) -> None:
        self.subscribers: dict[str, set[FakePubSub]] = {}

    def pubsub(self) -> FakePubSub:
        return FakePubSub(self)

    async def publish(self, channel: str, data: str) -> int:
        targets = list(self.subscribers.get(channel, set()))
        for target in targets:
            target.deliver({"type": "message", "data": data})
        return len(targets)


def _app(*, record: SessionRecord | None = None) -> tuple[TestClient, FakeBroker, StubSessions]:
    broker = FakeBroker()
    sessions = StubSessions(record if record is not None else _record(ACME_OPERATOR))
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_session_manager] = lambda: sessions
    app.dependency_overrides[get_approval_events_redis] = lambda: broker
    return TestClient(app), broker, sessions


def _cookie() -> str:
    return get_settings().session_cookie_name


def test_two_clients_see_ticket_creation_and_decision() -> None:
    client, broker, _sessions = _app()
    with client:
        client.cookies.set(_cookie(), "session-1")
        with (
            client.websocket_connect(
                "/ws/approvals", subprotocols=["bastion.csrf.csrf-1"]
            ) as first,
            client.websocket_connect(
                "/ws/approvals", subprotocols=["bastion.csrf.csrf-1"]
            ) as second,
        ):
            for socket in (first, second):
                assert socket.receive_json()["type"] == "connected"
                assert socket.receive_json()["type"] == "refresh"

            publish = partial(publish_approval_event, broker)
            client.portal.call(
                partial(
                    publish,
                    tenant_id="acme",
                    event_type=AuditEventType.APPROVAL_REQUESTED,
                    ticket_id="ticket-1",
                    tool_name="execute_file_write",
                )
            )
            client.portal.call(
                partial(
                    publish,
                    tenant_id="acme",
                    event_type=AuditEventType.APPROVAL_GRANTED,
                    ticket_id="ticket-1",
                    status="approved",
                    actor_id="bob-sub",
                )
            )

            for socket in (first, second):
                created = socket.receive_json()
                decided = socket.receive_json()
                assert created["type"] == "APPROVAL_REQUESTED"
                assert created["ticket_id"] == "ticket-1"
                assert decided["type"] == "APPROVAL_GRANTED"
                assert decided["status"] == "approved"


def test_socket_only_receives_its_own_tenant_events() -> None:
    client, broker, _sessions = _app()
    with client:
        client.cookies.set(_cookie(), "session-1")
        with client.websocket_connect(
            "/ws/approvals", subprotocols=["bastion.csrf.csrf-1"]
        ) as socket:
            assert socket.receive_json()["type"] == "connected"
            assert socket.receive_json()["type"] == "refresh"

            publish = partial(publish_approval_event, broker)
            client.portal.call(
                partial(
                    publish,
                    tenant_id="globex",
                    event_type=AuditEventType.APPROVAL_REQUESTED,
                    ticket_id="other-tenant",
                )
            )
            client.portal.call(
                partial(
                    publish,
                    tenant_id="acme",
                    event_type=AuditEventType.APPROVAL_REQUESTED,
                    ticket_id="own-tenant",
                )
            )
            assert socket.receive_json()["ticket_id"] == "own-tenant"


def test_readonly_role_is_rejected() -> None:
    client, _broker, _sessions = _app(record=_record(ACME_READONLY))
    with client:
        client.cookies.set(_cookie(), "session-1")
        with (
            pytest.raises(WebSocketDisconnect) as refusal,
            client.websocket_connect("/ws/approvals", subprotocols=["bastion.csrf.csrf-1"]),
        ):
            pass
    assert refusal.value.code == 4403


def test_missing_csrf_is_rejected() -> None:
    client, _broker, _sessions = _app()
    with client:
        client.cookies.set(_cookie(), "session-1")
        with (
            pytest.raises(WebSocketDisconnect) as refusal,
            client.websocket_connect("/ws/approvals"),
        ):
            pass
    assert refusal.value.code == 4403


def test_foreign_origin_is_rejected() -> None:
    client, _broker, _sessions = _app()
    with client:
        client.cookies.set(_cookie(), "session-1")
        with (
            pytest.raises(WebSocketDisconnect) as refusal,
            client.websocket_connect(
                "/ws/approvals",
                subprotocols=["bastion.csrf.csrf-1"],
                headers={"origin": "https://evil.example"},
            ),
        ):
            pass
    assert refusal.value.code == 4403


def test_handshake_echoes_the_offered_subprotocol() -> None:
    """RFC 6455: a browser aborts when the 101 omits the protocol it offered.

    The CSRF token rides in ``bastion.csrf.<token>`` because a browser cannot set
    headers on a WebSocket; the server must select that exact subprotocol or the
    connection dies before the first message and the page polls forever.
    """
    client, _broker, _sessions = _app()
    with client:
        client.cookies.set(_cookie(), "session-1")
        with client.websocket_connect(
            "/ws/approvals", subprotocols=["bastion.csrf.csrf-1"]
        ) as socket:
            assert socket.accepted_subprotocol == "bastion.csrf.csrf-1"
            assert socket.receive_json()["type"] == "connected"
            assert socket.receive_json()["type"] == "refresh"


def test_clients_that_offer_no_csrf_subprotocol_still_connect() -> None:
    """Non-browser clients use the query/header token and offer no protocol."""
    client, _broker, _sessions = _app()
    with client:
        client.cookies.set(_cookie(), "session-1")
        with client.websocket_connect("/ws/approvals?csrf_token=csrf-1") as socket:
            assert socket.accepted_subprotocol is None
            assert socket.receive_json()["type"] == "connected"

        # An unrelated protocol is not echoed: only the CSRF carrier is selected.
        with client.websocket_connect(
            "/ws/approvals?csrf_token=csrf-1", subprotocols=["graphql-ws"]
        ) as socket:
            assert socket.accepted_subprotocol is None
            assert socket.receive_json()["type"] == "connected"


async def test_pubsub_round_trip_and_malformed_message() -> None:
    redis = FakeAsyncRedis(decode_responses=True)
    stream = subscribe_approval_events(redis, "acme")  # type: ignore[arg-type]
    received = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    assert await publish_approval_event(
        redis,  # type: ignore[arg-type]
        tenant_id="acme",
        event_type=AuditEventType.APPROVAL_REQUESTED,
        ticket_id="ticket-1",
    )
    event = await asyncio.wait_for(received, timeout=2)
    assert event["type"] == "APPROVAL_REQUESTED"
    assert channel_for("acme") == "approvals:events:acme"
    await redis.publish(channel_for("acme"), "not-json")
    await stream.aclose()
    await redis.aclose()
