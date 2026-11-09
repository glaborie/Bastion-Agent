"""ARQ enqueue bridge for the gateway (ADR-010).

The gateway never executes a tool. When a ticket is approved it hands the
ticket id to the worker; if Redis is unavailable the approval still commits and
the worker's ``resume_approved_tickets_job`` cron sweep picks the ticket up.
"""

from __future__ import annotations

import logging

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from settings import get_settings

logger = logging.getLogger(__name__)

#: Fixed job-id prefix: approving twice cannot enqueue the same ticket twice.
_RESUME_JOB_PREFIX = "resume:"

_pool: ArqRedis | None = None


async def get_arq_pool() -> ArqRedis:
    """Return the process-wide ARQ pool, creating it on first use."""
    global _pool
    if _pool is None:
        settings = get_settings()
        redis_settings = RedisSettings.from_dsn(settings.redis_url)
        # Never let a dashboard request block on a dead Redis: fail fast and let
        # the worker's sweep do the work later.
        redis_settings.conn_timeout = int(settings.arq_connection_timeout_seconds)
        redis_settings.conn_retries = 0
        _pool = await create_pool(redis_settings)
    return _pool


async def enqueue_tool_resume(ticket_id: str) -> bool:
    """Ask the worker to execute an approved ticket.

    Returns ``True`` when the job was queued (or was already queued). A failure
    is logged and swallowed: the approval is already durable, and the cron sweep
    is the recovery path.
    """
    settings = get_settings()
    if not settings.tool_resume_auto_enqueue:
        return False
    try:
        pool = await get_arq_pool()
        await pool.enqueue_job(
            "resume_tool_job",
            ticket_id=ticket_id,
            _job_id=f"{_RESUME_JOB_PREFIX}{ticket_id}",
            _queue_name=settings.arq_queue_name,
        )
    # An enqueue failure must never fail the approval response: the decision is
    # already durable and the worker sweep is the recovery path.
    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning(
            "Could not enqueue approved ticket; the worker sweep will retry",
            extra={"ticket_id": ticket_id},
        )
        return False
    return True


async def close_arq_pool() -> None:
    """Release the ARQ connection pool (gateway shutdown)."""
    global _pool
    pool, _pool = _pool, None
    if pool is not None:
        await pool.aclose()
