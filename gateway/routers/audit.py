"""Audit-ledger API: paging, filtering, chain verification, session timelines."""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from db.audit import ChainVerification, verify_audit_chain
from db.models import AuditLog
from db.session import get_db_session
from gateway.audit_service import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    AuditFilters,
    list_records,
    next_page_url,
    session_timeline,
)
from gateway.auth.rbac import AuthContext, require_csrf, require_roles
from gateway.dashboard.templating import render
from gateway.web import is_htmx

router = APIRouter(tags=["audit"])


class AuditRecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    session_id: str | None
    actor_id: str
    event_type: str
    payload_hash: str
    previous_hash: str
    record_hash: str
    metadata_json: dict[str, Any]


@router.get("/api/audit", summary="Paginated audit ledger")
async def list_audit(
    request: Request,
    event_type: str | None = Query(default=None, max_length=64),
    actor_id: str | None = Query(default=None, max_length=128),
    session_id: str | None = Query(default=None, max_length=128),
    before_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    context: AuthContext = Depends(require_roles("operator", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> Any:
    filters = _filters(
        event_type=event_type,
        actor_id=actor_id,
        session_id=session_id,
        before_id=before_id,
        limit=limit,
    )
    page = await list_records(session, filters)
    if is_htmx(request):
        return _render_records(
            request,
            context,
            records=page.records,
            filters=filters,
            next_url=(
                next_page_url("/dashboard/audit", filters, page.next_before_id)
                if page.next_before_id
                else None
            ),
        )
    return {
        "records": [AuditRecordOut.model_validate(record) for record in page.records],
        "next_before_id": page.next_before_id,
        "has_more": page.has_more,
    }


@router.post("/api/audit/verify", summary="Verify the hash chain")
async def verify_chain(
    request: Request,
    limit: int | None = Query(default=None, ge=1, le=1_000_000),
    context: AuthContext = Depends(require_csrf),
    _authorized: AuthContext = Depends(require_roles("operator", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> Any:
    """Recompute every record hash and link (or the most recent ``limit``)."""
    try:
        result = await verify_audit_chain(session, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if is_htmx(request):
        return HTMLResponse(_verification_fragment(result))
    return {
        "ok": result.ok,
        "checked": result.checked,
        "first_bad_id": result.first_bad_id,
        "reason": result.reason,
    }


@router.get("/api/sessions/{session_id}/timeline", summary="Session audit timeline")
async def timeline(
    session_id: str,
    request: Request,
    context: AuthContext = Depends(require_roles("operator", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> Any:
    if not session_id or len(session_id) > 128:
        raise HTTPException(status_code=422, detail="invalid session id")
    records = await session_timeline(session, session_id)
    if is_htmx(request):
        return _render_records(
            request,
            context,
            records=records,
            filters=AuditFilters(session_id=session_id),
            next_url=None,
        )
    return {
        "session_id": session_id,
        "records": [AuditRecordOut.model_validate(record) for record in records],
        "count": len(records),
    }


def _filters(
    *,
    event_type: str | None,
    actor_id: str | None,
    session_id: str | None,
    before_id: int | None,
    limit: int,
) -> AuditFilters:
    try:
        return AuditFilters(
            event_type=event_type,
            actor_id=actor_id,
            session_id=session_id,
            before_id=before_id,
            limit=limit,
        ).validated()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _render_records(
    request: Request,
    context: AuthContext,
    *,
    records: list[AuditLog],
    filters: AuditFilters,
    next_url: str | None,
) -> HTMLResponse:
    return render(
        request,
        "partials/audit_table.html",
        context={
            "records": records,
            "filters": filters,
            "next_url": next_url,
            "principal": context.principal,
            "csrf_token": context.csrf_token,
        },
    )


def _verification_fragment(result: ChainVerification) -> str:
    if result.ok:
        return (
            '<p><span class="badge badge-ok">intact</span> '
            f"{result.checked} record(s) verified.</p>"
        )
    return (
        '<p><span class="badge badge-bad">tampered</span> '
        f"first bad id {result.first_bad_id}: {html.escape(result.reason or 'hash mismatch')}</p>"
    )
