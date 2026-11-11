"""Demo console: list allow-listed scenarios and start one (ADR-007).

The page is the browser-first path through the scripts in ``scripts/``. A run
request carries a scenario id and nothing else: the callable is resolved from
:data:`agent.demo.scenarios.SCENARIOS` on the worker, so no request field can
name a command, a script path or argv.

Execution model: the gateway writes a ``queued`` run record to Redis and
enqueues an ARQ job. The worker resolves the id, runs the scenario, and updates
the record; the page polls the record. The run writes structured logs only —
the canonical audit rows come from the scenario's own effects (chat turn,
approval ticket), never from a new event type (ADR-007 decision 7).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from redis.asyncio import Redis

from agent.demo.runs import (
    STATUS_FAILED,
    STATUS_QUEUED,
    DemoRun,
    DemoRunUnavailableError,
    load_run,
    new_run_id,
    save_run,
    utc_now_iso,
)
from agent.demo.scenarios import DemoScenario, UnknownScenarioError, get_scenario
from db.redis import get_redis
from gateway.auth.rbac import AuthContext, require_csrf, require_roles
from gateway.dashboard.templating import render, render_error
from gateway.queue import enqueue_demo_run
from gateway.rate_limit import rate_limit
from settings import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["demo"],
    include_in_schema=False,
    dependencies=[Depends(rate_limit("dashboard"))],
)


def get_demo_redis() -> Redis:
    """Run-store client; a dependency so tests can point it at a fake server."""
    return get_redis(get_settings().redis_url)


def _scenario_for(run: DemoRun) -> DemoScenario | None:
    try:
        return get_scenario(run.scenario_id)
    except UnknownScenarioError:
        return None


@router.post("/dashboard/demo/runs", response_class=HTMLResponse)
async def start_demo_run(
    request: Request,
    scenario_id: str = Form(..., max_length=64),
    context: AuthContext = Depends(require_csrf),
    _authorized: AuthContext = Depends(require_roles("operator", "admin")),
    redis: Redis = Depends(get_demo_redis),
) -> HTMLResponse:
    """Start one registry scenario as the signed-in principal."""
    try:
        scenario = get_scenario(scenario_id)
    except UnknownScenarioError:
        raise HTTPException(status_code=404, detail="unknown demo scenario") from None
    if not scenario.runnable:
        raise HTTPException(status_code=422, detail="scenario is CLI-only")

    run_id = new_run_id()
    run = DemoRun(
        run_id=run_id,
        scenario_id=scenario.id,
        status=STATUS_QUEUED,
        actor_id=context.actor_id,
        session_id=f"demo-{run_id}",
        created_at=utc_now_iso(),
    )
    try:
        await save_run(redis, run)
        queued = await enqueue_demo_run(
            run_id=run_id,
            scenario_id=scenario.id,
            actor_id=context.actor_id,
            tenant_id=context.tenant_id,
            roles=sorted(context.principal.roles),
            session_id=run.session_id,
        )
    except DemoRunUnavailableError as exc:
        return render(
            request,
            "partials/demo_run.html",
            context={
                "principal": context.principal,
                "csrf_token": context.csrf_token,
                "run": run,
                "scenario": scenario,
                "error": str(exc),
            },
            status_code=503,
        )
    if not queued:
        failed = DemoRun(
            run_id=run_id,
            scenario_id=scenario.id,
            status=STATUS_FAILED,
            actor_id=context.actor_id,
            session_id=run.session_id,
            created_at=run.created_at,
            finished_at=utc_now_iso(),
            error="the job queue is unavailable; check Redis and the worker",
        )
        try:
            await save_run(redis, failed)
        except DemoRunUnavailableError:
            logger.warning("Could not record a failed demo run", extra={"run_id": run_id})
        return render(
            request,
            "partials/demo_run.html",
            context={
                "principal": context.principal,
                "csrf_token": context.csrf_token,
                "run": failed,
                "scenario": scenario,
            },
            status_code=503,
        )

    logger.info(
        "Demo scenario queued",
        extra={"scenario": scenario.id, "run_id": run_id, "actor_id": context.actor_id},
    )
    return render(
        request,
        "partials/demo_run.html",
        context={
            "principal": context.principal,
            "csrf_token": context.csrf_token,
            "run": run,
            "scenario": scenario,
        },
    )


@router.get("/api/dashboard/demo/runs/{run_id}", response_class=HTMLResponse)
async def demo_run_status(
    request: Request,
    run_id: str,
    context: AuthContext = Depends(require_roles("operator", "admin")),
    redis: Redis = Depends(get_demo_redis),
) -> HTMLResponse:
    """Poll one run; the partial stops polling itself once it is terminal."""
    if not run_id or len(run_id) > 64:
        raise HTTPException(status_code=422, detail="malformed run id")
    try:
        run = await load_run(redis, run_id)
    except DemoRunUnavailableError as exc:
        return render_error(
            request,
            title="Run store unavailable",
            detail=str(exc),
            status_code=503,
        )
    if run is None:
        return render_error(
            request,
            title="Run not found",
            detail="That demo run expired or never existed.",
            status_code=404,
        )
    return render(
        request,
        "partials/demo_run.html",
        context={
            "principal": context.principal,
            "csrf_token": context.csrf_token,
            "run": run,
            "scenario": _scenario_for(run),
        },
    )
