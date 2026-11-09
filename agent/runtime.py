"""ARQ worker entrypoint and guarded tool jobs (Milestone 4).

The worker owns tool execution, so the gateway never runs a mutating tool in the
request process. Jobs are intentionally thin: all policy lives in
:mod:`agent.tools.execution`, which is shared with the gateway and covered by
tests.

``resume_approved_tickets_job`` runs on a cron timer and executes tickets
approved but not yet run. Normally the gateway enqueues ``resume_tool_job``
immediately after the decision; the sweep is the safety net for a Redis outage,
a worker restart, or ``TOOL_RESUME_AUTO_ENQUEUE`` being disabled.

``expire_stale_approvals_job`` closes tickets whose approval window lapsed while
nobody was looking, so the queue only lists actionable work. The ticket history
stays in the audit ledger; until the sweep runs (at most 30 s) the dashboard
shows the ticket as expired and locked.
"""

from __future__ import annotations

import json
import logging
from typing import Any, ClassVar

from arq import cron
from arq.connections import RedisSettings

from agent.routing.client import close_model_router
from agent.tools.decorator import (
    AgentContext,
    ToolArgumentError,
    ToolAuthorizationError,
    ToolError,
    ToolNotFoundError,
    ToolStatus,
)
from agent.tools.execution import (
    ApprovalExecutionError,
    approved_ticket_ids,
    expire_stale_approvals,
    request_tool_execution,
    resume_approved_tool,
)
from db.session import dispose_engine, init_models, session_scope
from logging_setup import configure_logging
from settings import get_settings
from telemetry import configure_tracing, shutdown_tracing

logger = logging.getLogger(__name__)


async def startup(ctx: dict[str, Any]) -> None:
    """Prepare the worker before it starts consuming jobs."""
    settings = get_settings()
    configure_logging(settings.log_level)
    configure_tracing(settings)
    await init_models()
    logger.info(
        "Bastion-Agent worker ready",
        extra={
            "environment": settings.environment,
            "queue": WorkerSettings.queue_name,
        },
    )


async def worker_healthcheck(ctx: dict[str, Any]) -> dict[str, str]:
    """Trivial queue job proving Redis and the worker pool are wired up."""
    return {"status": "ok", "queue": WorkerSettings.queue_name}


async def execute_tool_job(
    ctx: dict[str, Any],
    *,
    tool_name: str,
    actor_id: str,
    roles: list[str] | None = None,
    session_id: str,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Authorize and either run a read-only tool or suspend a mutating one.

    ``actor_id`` must be the caller's OIDC subject (JWT ``sub``), because the
    approval decision compares it with the approver's subject.
    """
    settings = get_settings()
    try:
        encoded = json.dumps(arguments or {}, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        return {"status": "invalid_arguments", "tool": tool_name, "error": "not JSON"}
    if len(encoded) > settings.tool_max_argument_bytes:
        return {
            "status": "invalid_arguments",
            "tool": tool_name,
            "error": "arguments_too_large",
        }

    try:
        context = AgentContext(
            actor_id=actor_id,
            roles=frozenset(roles or ()),
            session_id=session_id,
            request_id=ctx.get("job_id"),
        )
    except ValueError as exc:
        return {"status": "invalid_context", "tool": tool_name, "error": str(exc)}

    try:
        async with session_scope() as session:
            result = await request_tool_execution(
                session,
                tool_name=tool_name,
                arguments=arguments,
                context=context,
            )
    except ToolAuthorizationError as exc:
        return {"status": "denied", "tool": tool_name, "error": str(exc)}
    except ToolArgumentError as exc:
        return {"status": "invalid_arguments", "tool": tool_name, "error": str(exc)}
    except ToolNotFoundError as exc:
        return {"status": "unknown_tool", "tool": tool_name, "error": str(exc)}
    except ToolError as exc:
        return {"status": "error", "tool": tool_name, "error": str(exc)}
    return result.to_payload()


async def resume_tool_job(ctx: dict[str, Any], *, ticket_id: str) -> dict[str, Any]:
    """Execute an approved ticket; safe to call more than once."""
    try:
        async with session_scope() as session:
            result = await resume_approved_tool(session, ticket_id=ticket_id)
    except ApprovalExecutionError as exc:
        logger.info(
            "Ticket not resumable",
            extra={"ticket_id": ticket_id, "code": exc.code},
        )
        return {"status": exc.code, "ticket_id": ticket_id, "error": str(exc)}
    except ToolError as exc:  # pragma: no cover - defensive
        return {"status": "error", "ticket_id": ticket_id, "error": str(exc)}
    payload = result.to_payload()
    payload["ticket_id"] = ticket_id
    return payload


async def expire_stale_approvals_job(ctx: dict[str, Any]) -> dict[str, int]:
    """Cron sweep: close tickets whose approval window has closed."""
    async with session_scope() as session:
        expired = await expire_stale_approvals(session)
    return {"expired": expired}


async def resume_approved_tickets_job(ctx: dict[str, Any]) -> dict[str, int]:
    """Cron safety net: execute approved tickets that no job picked up."""
    async with session_scope() as session:
        ticket_ids = await approved_ticket_ids(session)
    executed = failed = 0
    for ticket_id in ticket_ids:
        try:
            async with session_scope() as session:
                result = await resume_approved_tool(session, ticket_id=ticket_id)
        except ApprovalExecutionError:
            failed += 1
            continue
        if result.status is ToolStatus.EXECUTED:
            executed += 1
        elif result.status is ToolStatus.FAILED:
            failed += 1
    if ticket_ids:
        logger.info(
            "Approved-ticket sweep complete",
            extra={"approved": len(ticket_ids), "executed": executed, "failed": failed},
        )
    return {"approved": len(ticket_ids), "executed": executed, "failed": failed}


async def shutdown(ctx: dict[str, Any]) -> None:
    """Release resources when the worker receives a shutdown signal."""
    shutdown_tracing()
    await close_model_router()
    await dispose_engine()
    logger.info("Bastion-Agent worker stopped")


class WorkerSettings:
    """ARQ configuration consumed by ``arq agent.runtime.WorkerSettings``."""

    functions: ClassVar[list[Any]] = [
        worker_healthcheck,
        execute_tool_job,
        resume_tool_job,
        expire_stale_approvals_job,
        resume_approved_tickets_job,
    ]
    cron_jobs: ClassVar[list[Any]] = [
        cron(expire_stale_approvals_job, second={0, 30}),
        cron(resume_approved_tickets_job, second={15, 45}),
    ]
    redis_settings: ClassVar[RedisSettings] = RedisSettings.from_dsn(get_settings().redis_url)
    queue_name: ClassVar[str] = get_settings().arq_queue_name
    on_startup: ClassVar[Any] = startup
    on_shutdown: ClassVar[Any] = shutdown
    job_timeout: ClassVar[int] = 300
    max_tries: ClassVar[int] = 3
    keep_result: ClassVar[int] = 3600
