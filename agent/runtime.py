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

``purge_expired_payload_escrow_job`` deletes pre-production escrow rows past
their retention window (ADR-005 decision 7). It never touches ``audit_logs``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import replace
from typing import Any, ClassVar

from arq import cron
from arq.connections import RedisSettings
from opentelemetry import trace
from opentelemetry.util.types import AttributeValue
from redis.asyncio import Redis

from agent.approvals_events import publish_approval_event
from agent.demo.runs import (
    STATUS_FAILED,
    STATUS_RUNNING,
    STATUS_SUCCEEDED,
    DemoRun,
    DemoRunUnavailableError,
    load_run,
    save_run,
    utc_now_iso,
)
from agent.demo.scenarios import (
    DemoScenarioError,
    ScenarioContext,
    UnknownScenarioError,
    get_scenario,
)
from agent.job_auth import (
    DEMO_JOB,
    RESUME_JOB,
    TOOL_JOB,
    JobSignatureError,
    demo_job_fields,
    resume_job_fields,
    tool_job_fields,
    verify_and_consume,
)
from agent.routing.client import close_model_router
from agent.tools.decorator import (
    TOOL_NOT_IN_CATALOG_CODE,
    AgentContext,
    ToolArgumentError,
    ToolAuthorizationError,
    ToolCatalogUnavailableError,
    ToolError,
    ToolNotFoundError,
    ToolNotInCatalogError,
    ToolStatus,
    verify_registry,
)
from agent.tools.execution import (
    ApprovalExecutionError,
    approved_ticket_ids,
    expire_stale_approvals,
    record_tool_refusal,
    request_tool_execution,
    resume_approved_tool,
)
from db.escrow import purge_expired_escrow
from db.export import export_ledger
from db.models import AuditEventType
from db.redis import arq_redis_settings, get_redis
from db.session import dispose_engine, init_models, session_scope
from logging_setup import configure_logging
from settings import get_settings
from telemetry import configure_tracing, shutdown_tracing, span_attributes

logger = logging.getLogger(__name__)

#: Resolves to the provider the worker installs at startup. Jobs are the only
#: traced work: the two cron sweeps run every 30 s and would be pure noise.
_tracer = trace.get_tracer(__name__)


async def startup(ctx: dict[str, Any]) -> None:
    """Prepare the worker before it starts consuming jobs."""
    settings = get_settings()
    configure_logging(settings.log_level)
    configure_tracing(settings)
    # Gate 1: refuse to run with a registered tool the catalog has not approved.
    verify_registry()
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


def _outcome_attributes(payload: Mapping[str, Any]) -> dict[str, AttributeValue]:
    """Status, ticket and refusal code of a finished job.

    Arguments are deliberately absent: the ledger keeps the hash and the keys,
    the trace keeps the verdict.
    """
    status = payload.get("status")
    ticket_id = payload.get("ticket_id")
    code = payload.get("code")
    return span_attributes(
        {
            "bastion.tool.status": status if isinstance(status, str) else None,
            "bastion.approval.ticket_id": str(ticket_id) if ticket_id is not None else None,
            "bastion.tool.code": code if isinstance(code, int) else None,
        }
    )


async def execute_tool_job(
    ctx: dict[str, Any],
    *,
    tool_name: str,
    actor_id: str,
    tenant_id: str,
    session_id: str,
    roles: list[str] | None = None,
    arguments: dict[str, Any] | None = None,
    job_nonce: str = "",
    job_expires_at: str = "",
    job_signature: str = "",
) -> dict[str, Any]:
    """Authorize and either run a read-only tool or suspend a mutating one.

    ``actor_id`` must be the caller's OIDC subject (JWT ``sub``), because the
    approval decision compares it with the approver's subject.

    The identity in this payload is only accepted when the envelope proves a
    trusted enqueuer minted it (ADR-018). Anything else is refused before the
    guard runs, so a forged principal cannot reach the ledger, create a ticket
    or execute a tool.

    One span per job, named after the tool, so the worker half of a four-eyes
    decision is visible next to the gateway span that approved it.
    """
    with _tracer.start_as_current_span(f"tool.execute {tool_name}") as span:
        span.set_attributes(
            span_attributes(
                {
                    "bastion.tool.name": tool_name,
                    "bastion.audit.session_id": session_id,
                }
            )
        )
        rejected = await _reject_unsigned_job(
            span,
            TOOL_JOB,
            tool_job_fields(
                tool_name=tool_name,
                actor_id=actor_id,
                tenant_id=tenant_id,
                session_id=session_id,
                roles=roles,
                arguments=arguments,
            ),
            nonce=job_nonce,
            expires_at=job_expires_at,
            signature=job_signature,
        )
        if rejected is not None:
            return {"status": "unauthorized_job", "tool": tool_name, "error": rejected}
        result = await _run_tool_job(
            ctx,
            tool_name=tool_name,
            actor_id=actor_id,
            tenant_id=tenant_id,
            roles=roles,
            session_id=session_id,
            arguments=arguments,
        )
        span.set_attributes(_outcome_attributes(result))
        return result


async def _reject_unsigned_job(
    span: trace.Span,
    kind: str,
    fields: Mapping[str, Any],
    *,
    nonce: str,
    expires_at: str,
    signature: str,
) -> str | None:
    """Verify a job envelope; return a rejection reason or ``None``.

    A rejection is deliberately not written to the audit ledger: the only
    identity available is the forged one, and a hash-chained row naming an
    attacker-chosen principal is worse than a log line. The span and the worker
    log carry the reason, and the refusal happens before any guard, ticket or
    execution row exists.
    """
    settings = get_settings()
    try:
        await verify_and_consume(
            get_redis(settings.redis_url),
            kind,
            fields,
            nonce=nonce,
            expires_at=expires_at,
            signature=signature,
            secret=settings.job_signing_secret.get_secret_value(),
            ttl_seconds=settings.job_signature_ttl_seconds,
        )
    except JobSignatureError as exc:
        logger.error(
            "Rejected a job whose identity was not minted by a trusted enqueuer",
            extra={"job": kind, "reason": exc.reason},
        )
        span.set_attribute("bastion.job.rejected", exc.reason)
        return exc.reason
    # A worker that cannot read Redis cannot prove single use; the queue is a
    # Redis list, so this is an outage path rather than a reachable state.
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Could not verify a job signature", extra={"job": kind})
        span.set_attribute("bastion.job.rejected", "signature_unverifiable")
        return "signature_unverifiable"
    return None


async def _run_tool_job(
    ctx: dict[str, Any],
    *,
    tool_name: str,
    actor_id: str,
    tenant_id: str,
    roles: list[str] | None,
    session_id: str,
    arguments: dict[str, Any] | None,
) -> dict[str, Any]:
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
            tenant_id=tenant_id,
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
        await _persist_refusal(tool_name, context, exc, arguments)
        return {"status": "denied", "tool": tool_name, "error": str(exc)}
    except ToolArgumentError as exc:
        return {"status": "invalid_arguments", "tool": tool_name, "error": str(exc)}
    except ToolNotInCatalogError as exc:
        # ADR-009 Gate 1: the same -32003 code as a name that does not exist.
        await _persist_refusal(tool_name, context, exc, arguments)
        return {
            "status": "unknown_tool",
            "tool": tool_name,
            "error": str(exc),
            "code": exc.code,
        }
    except ToolNotFoundError as exc:
        await _persist_refusal(tool_name, context, exc, arguments)
        return {
            "status": "unknown_tool",
            "tool": tool_name,
            "error": str(exc),
            "code": TOOL_NOT_IN_CATALOG_CODE,
        }
    except ToolCatalogUnavailableError as exc:
        await _persist_refusal(tool_name, context, exc, arguments)
        return {"status": "error", "tool": tool_name, "error": str(exc)}
    except ToolError as exc:
        return {"status": "error", "tool": tool_name, "error": str(exc)}

    if result.status is ToolStatus.APPROVAL_PENDING and result.ticket_id:
        await publish_approval_event(
            get_redis(settings.redis_url),
            tenant_id=tenant_id,
            event_type=AuditEventType.APPROVAL_REQUESTED,
            ticket_id=result.ticket_id,
            tool_name=tool_name,
        )
    return result.to_payload()


async def _persist_refusal(
    tool_name: str,
    context: AgentContext,
    error: ToolError,
    arguments: dict[str, Any] | None,
) -> None:
    """Commit a refusal in a fresh transaction.

    The guarded request runs in ``session_scope``, which rolls back when the
    guard raises — including the audit row the guard wrote. A refusal is exactly
    the event an operator must be able to find later, so it is re-recorded here
    in its own transaction. The first write never committed, so the ledger holds
    one row, not two.
    """
    try:
        async with session_scope() as session:
            await record_tool_refusal(
                session,
                context=context,
                tool_name=tool_name,
                error=error,
                arguments=arguments,
            )
    except Exception:  # pylint: disable=broad-exception-caught
        # Losing the audit row must not turn a refusal into a failure open, but
        # it is loud: the worker log is the fallback record.
        logger.exception(
            "Could not record a refused tool call",
            extra={"tool": tool_name, "actor_id": context.actor_id},
        )


async def resume_tool_job(
    ctx: dict[str, Any],
    *,
    ticket_id: str,
    tenant_id: str = "",
    job_nonce: str = "",
    job_expires_at: str = "",
    job_signature: str = "",
) -> dict[str, Any]:
    """Execute an approved ticket; safe to call more than once.

    The ticket id is harmless to guess — execution re-derives the initiator,
    tenant and role from the row and re-checks four-eyes — but the job is signed
    anyway so every enqueue site shares one mint/verify path (ADR-018).

    The span carries the ticket id, the same attribute the gateway puts on the
    four-eyes decision, so the two traces join on the approval in the ledger.
    """
    with _tracer.start_as_current_span("tool.resume") as span:
        span.set_attribute("bastion.approval.ticket_id", ticket_id)
        rejected = await _reject_unsigned_job(
            span,
            RESUME_JOB,
            resume_job_fields(ticket_id=ticket_id, tenant_id=tenant_id),
            nonce=job_nonce,
            expires_at=job_expires_at,
            signature=job_signature,
        )
        if rejected is not None:
            return {"status": "unauthorized_job", "ticket_id": ticket_id, "error": rejected}
        try:
            async with session_scope() as session:
                result = await resume_approved_tool(session, ticket_id=ticket_id)
        except ApprovalExecutionError as exc:
            span.set_attribute("error.type", type(exc).__name__)
            logger.info(
                "Ticket not resumable",
                extra={"ticket_id": ticket_id, "code": exc.code},
            )
            payload = {"status": exc.code, "ticket_id": ticket_id, "error": str(exc)}
        except ToolError as exc:  # pragma: no cover - defensive
            span.set_attribute("error.type", type(exc).__name__)
            payload = {"status": "error", "ticket_id": ticket_id, "error": str(exc)}
        else:
            payload = result.to_payload()
            payload["ticket_id"] = ticket_id
        span.set_attributes(_outcome_attributes(payload))
        return payload


async def expire_stale_approvals_job(ctx: dict[str, Any]) -> dict[str, int]:
    """Cron sweep: close tickets whose approval window has closed."""
    async with session_scope() as session:
        expired = await expire_stale_approvals(session)
    return {"expired": expired}


async def purge_expired_payload_escrow_job(ctx: dict[str, Any]) -> dict[str, int]:
    """Cron sweep: hard-delete escrow rows past ``expires_at``.

    Off by default and always empty in production; the statement is cheap on an
    empty table because ``ix_payload_escrow_expires_at`` covers it.
    """
    async with session_scope() as session:
        purged = await purge_expired_escrow(session)
    if purged:
        logger.info("Payload-escrow purge complete", extra={"purged": purged})
    return {"purged": purged}


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


async def export_audit_ledger_job(ctx: dict[str, Any]) -> dict[str, int]:
    """Page the ledger into signed, locked segments (ADR-005 decision 10).

    Not on a cron timer: when a deployment runs it, and at what cadence, is an
    operator decision, and the store is opt-in. An unreachable store raises, so
    an enqueued export fails visibly instead of reporting a green no-op.
    """
    async with session_scope() as session:
        segments = await export_ledger(session)
    records = sum(segment.manifest.records for segment in segments)
    logger.info(
        "Audit ledger export complete",
        extra={"segments": len(segments), "records": records},
    )
    return {"segments": len(segments), "records": records}


async def run_demo_scenario_job(
    _ctx: dict[str, Any],
    *,
    run_id: str,
    scenario_id: str,
    actor_id: str,
    tenant_id: str,
    roles: list[str],
    session_id: str,
    job_nonce: str = "",
    job_expires_at: str = "",
    job_signature: str = "",
) -> dict[str, Any]:
    """Execute one allow-listed demo scenario and record its outcome.

    The gateway never runs a scenario in the request process. The actor and the
    roles were captured from the authenticated session before the job was
    queued; this function never sees the HTTP request, which is exactly why the
    envelope is checked before the scenario runs (ADR-018).
    """
    settings = get_settings()
    redis = get_redis(settings.redis_url)
    with _tracer.start_as_current_span("demo.scenario") as span:
        span.set_attributes(
            span_attributes(
                {
                    "bastion.demo.run_id": run_id,
                    "bastion.demo.scenario": scenario_id,
                }
            )
        )
        rejected = await _reject_unsigned_job(
            span,
            DEMO_JOB,
            demo_job_fields(
                run_id=run_id,
                scenario_id=scenario_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                roles=roles,
                session_id=session_id,
            ),
            nonce=job_nonce,
            expires_at=job_expires_at,
            signature=job_signature,
        )
        if rejected is not None:
            return {"status": "unauthorized_job", "run_id": run_id, "error": rejected}
        run = await load_run(redis, run_id)
        if run is None:
            logger.warning(
                "Demo run record disappeared before the job started",
                extra={"run_id": run_id, "scenario": scenario_id},
            )
            span.set_attribute("bastion.demo.status", "unknown_run")
            return {"status": "unknown_run", "run_id": run_id}

        await save_run(redis, replace(run, status=STATUS_RUNNING))
        try:
            scenario = get_scenario(scenario_id)
            handler = scenario.handler
            if handler is None:
                raise DemoScenarioError("scenario is CLI-only")
            outcome = await handler(
                ScenarioContext(
                    run_id=run_id,
                    actor_id=actor_id,
                    tenant_id=tenant_id,
                    actor_roles=frozenset(roles),
                    session_id=session_id,
                )
            )
        # A demo failure is recorded for the operator; the worker stays up.
        except (DemoScenarioError, UnknownScenarioError, DemoRunUnavailableError) as exc:
            await _fail_demo_run(redis, run, exc)
            span.set_attribute("bastion.demo.status", STATUS_FAILED)
            return {"status": STATUS_FAILED, "run_id": run_id, "error": str(exc)}
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.exception("Demo scenario failed", extra={"scenario": scenario_id})
            await _fail_demo_run(redis, run, exc)
            span.set_attribute("bastion.demo.status", STATUS_FAILED)
            return {
                "status": STATUS_FAILED,
                "run_id": run_id,
                "error": type(exc).__name__,
            }

        try:
            await save_run(
                redis,
                replace(
                    run,
                    status=STATUS_SUCCEEDED,
                    finished_at=utc_now_iso(),
                    summary=outcome.summary,
                    facts=outcome.facts,
                    lines=outcome.lines,
                    links=outcome.links,
                ),
            )
        except DemoRunUnavailableError:
            logger.exception("Could not record a finished demo run", extra={"run_id": run_id})
            return {"status": STATUS_FAILED, "run_id": run_id, "error": "run_store_unavailable"}
        span.set_attribute("bastion.demo.status", STATUS_SUCCEEDED)
        logger.info(
            "Demo scenario finished",
            extra={"scenario": scenario_id, "run_id": run_id, "actor_id": actor_id},
        )
        return {"status": STATUS_SUCCEEDED, "run_id": run_id}


async def _fail_demo_run(
    redis: Redis,
    run: DemoRun,
    exc: Exception,
) -> None:
    """Best-effort failure record; the span and the log remain the fallback."""
    message = f"{type(exc).__name__}: {exc}"
    try:
        await save_run(
            redis,
            replace(
                run,
                status=STATUS_FAILED,
                finished_at=utc_now_iso(),
                error=message[:400],
            ),
        )
    except DemoRunUnavailableError:
        logger.exception("Could not record a failed demo run", extra={"run_id": run.run_id})


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
        purge_expired_payload_escrow_job,
        export_audit_ledger_job,
        run_demo_scenario_job,
    ]
    cron_jobs: ClassVar[list[Any]] = [
        cron(expire_stale_approvals_job, second={0, 30}),
        cron(resume_approved_tickets_job, second={15, 45}),
        # Escrow rows are measured in hours; four sweeps an hour is plenty and
        # keeps each delete small.
        cron(purge_expired_payload_escrow_job, minute={0, 15, 30, 45}),
    ]
    redis_settings: ClassVar[RedisSettings] = arq_redis_settings()
    queue_name: ClassVar[str] = get_settings().arq_queue_name
    on_startup: ClassVar[Any] = startup
    on_shutdown: ClassVar[Any] = shutdown
    job_timeout: ClassVar[int] = 300
    max_tries: ClassVar[int] = 3
    keep_result: ClassVar[int] = 3600
