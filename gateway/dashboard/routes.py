"""Server-rendered pages of the Command Control Center (ADR-007)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from db.session import get_db_session
from gateway.approvals import list_pending
from gateway.audit_service import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    AuditFilters,
    event_type_choices,
    list_records,
    next_page_url,
    session_timeline,
)
from gateway.auth.rbac import AuthContext, require_roles
from gateway.dashboard.templating import render, render_error
from gateway.evals import load_latest_report
from settings import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dashboard"], include_in_schema=False)


@router.get("/")
async def index() -> RedirectResponse:
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(
    request: Request,
    context: AuthContext = Depends(require_roles("operator", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> HTMLResponse:
    settings = get_settings()
    approvals = await list_pending(
        session,
        viewer_id=context.actor_id,
        viewer_roles=context.principal.roles,
        limit=settings.approval_page_size,
    )
    return render(
        request,
        "dashboard.html",
        context={
            "principal": context.principal,
            "csrf_token": context.csrf_token,
            "approvals": approvals,
            "pending_count": len(approvals),
            "report": load_latest_report(settings.eval_report_path),
        },
    )


@router.get("/dashboard/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    event_type: str | None = Query(default=None, max_length=64),
    actor_id: str | None = Query(default=None, max_length=128),
    session_id: str | None = Query(default=None, max_length=128),
    before_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    context: AuthContext = Depends(require_roles("operator", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> HTMLResponse:
    try:
        filters = AuditFilters(
            event_type=event_type,
            actor_id=actor_id,
            session_id=session_id,
            before_id=before_id,
            limit=limit,
        ).validated()
    except ValueError as exc:
        return render_error(
            request,
            title="Invalid filter",
            detail=str(exc),
            status_code=422,
        )

    page = await list_records(session, filters)
    return render(
        request,
        "audit.html",
        context={
            "principal": context.principal,
            "csrf_token": context.csrf_token,
            "records": page.records,
            "filters": filters,
            "event_types": event_type_choices(),
            "next_url": (
                next_page_url("/dashboard/audit", filters, page.next_before_id)
                if page.next_before_id
                else None
            ),
        },
    )


@router.get("/dashboard/sessions/{session_id}", response_class=HTMLResponse)
async def session_page(
    request: Request,
    session_id: str,
    context: AuthContext = Depends(require_roles("operator", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> HTMLResponse:
    if not session_id or len(session_id) > 128:
        return render_error(
            request, title="Invalid session", detail="Malformed session id.", status_code=422
        )
    events = await session_timeline(session, session_id)
    return render(
        request,
        "session.html",
        context={
            "principal": context.principal,
            "csrf_token": context.csrf_token,
            "session_id": session_id,
            "events": events,
        },
    )
