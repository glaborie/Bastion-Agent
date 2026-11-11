"""Approval event bus shared by the worker, the gateway and the dashboard.

The ARQ worker creates tickets in a different process from the gateway that
serves the dashboard, so an in-process callback cannot reach every browser. The
bus is therefore Redis pub/sub: the worker and the decision route publish, and
each ``/ws/approvals`` connection subscribes to its own authenticated tenant's
channel. A publish failure is logged and swallowed — the ticket or decision is
already durable, and the dashboard's polling fallback is the recovery path
(ADR-007 decision 3, ADR-015).

Messages carry identifiers and verdicts only. Tool arguments, reasons and model
text never enter the bus; the dashboard re-reads the queue through its
tenant-scoped HTTP route after each event.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any, Final

from redis.asyncio import Redis
from redis.exceptions import RedisError

from db.models import AuditEventType
from db.tenancy import normalise_tenant_id

logger = logging.getLogger(__name__)

APPROVAL_EVENT_CHANNEL_PREFIX: Final[str] = "approvals:events:"


def channel_for(tenant_id: str) -> str:
    """Tenant-qualified channel name; a browser cannot subscribe to another tenant."""
    return f"{APPROVAL_EVENT_CHANNEL_PREFIX}{normalise_tenant_id(tenant_id)}"


def _event_payload(
    *,
    event_type: AuditEventType,
    ticket_id: str,
    tool_name: str | None,
    status: str | None,
    actor_id: str | None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "type": event_type.value,
        "ticket_id": ticket_id,
        "emitted_at": datetime.now(UTC).isoformat(),
    }
    if tool_name:
        event["tool"] = tool_name
    if status:
        event["status"] = status
    if actor_id:
        event["actor_id"] = actor_id
    return event


async def publish_approval_event(
    redis: Redis,
    *,
    tenant_id: str,
    event_type: AuditEventType,
    ticket_id: str,
    tool_name: str | None = None,
    status: str | None = None,
    actor_id: str | None = None,
) -> bool:
    """Publish one event; return ``False`` when Redis could not accept it.

    The caller must not turn a failed publish into a failed approval or
    decision: the durable write already committed and polling still works.
    """
    payload = _event_payload(
        event_type=event_type,
        ticket_id=ticket_id,
        tool_name=tool_name,
        status=status,
        actor_id=actor_id,
    )
    try:
        await asyncio.wait_for(
            redis.publish(channel_for(tenant_id), json.dumps(payload, separators=(",", ":"))),
            timeout=1.0,
        )
    except (RedisError, TimeoutError) as exc:
        logger.warning(
            "Could not publish an approval event; polling remains the fallback",
            extra={"event": event_type.value, "error": type(exc).__name__},
        )
        return False
    return True


async def subscribe_approval_events(
    redis: Redis, tenant_id: str
) -> AsyncGenerator[dict[str, Any], None]:
    """Yield decoded events for one tenant until the generator is closed."""
    channel = channel_for(tenant_id)
    pubsub = redis.pubsub()
    try:
        await pubsub.subscribe(channel)
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if not message or message.get("type") != "message":
                continue
            raw = message.get("data")
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            if not isinstance(raw, str):
                continue
            try:
                event = json.loads(raw)
            except ValueError:
                logger.warning("Discarding a malformed approval event")
                continue
            if isinstance(event, dict):
                yield event
    finally:
        try:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()  # type: ignore[no-untyped-call]
        except RedisError:  # pragma: no cover - connection already gone
            logger.debug("Approval subscription closed after a Redis error")
