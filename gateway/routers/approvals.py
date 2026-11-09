"""Four-eyes approval queue API (JSON for clients, HTML for HTMX)."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from db.session import get_db_session
from gateway.approvals import (
    ApprovalDecisionError,
    ApprovalView,
    decide_ticket,
    list_pending,
    parse_action,
    utc_isoformat,
)
from gateway.auth.rbac import AuthContext, require_csrf, require_roles
from gateway.dashboard.templating import render
from gateway.queue import enqueue_tool_resume
from gateway.web import is_htmx
from settings import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["approvals"])


class ApprovalOut(BaseModel):
    ticket_id: str
    tool_name: str
    tool_arguments: dict[str, Any]
    initiator_id: str
    required_role: str
    status: str
    token_expires_at: str
    expires_in: str
    decidable: bool
    expired: bool

    @classmethod
    def from_view(cls, view: ApprovalView) -> ApprovalOut:
        return cls(
            ticket_id=view.ticket_id,
            tool_name=view.tool_name,
            tool_arguments=view.tool_arguments,
            initiator_id=view.initiator_id,
            required_role=view.required_role,
            status=view.status,
            token_expires_at=utc_isoformat(view.token_expires_at),
            expires_in=view.expires_in,
            decidable=view.decidable,
            expired=view.expired,
        )


def _render_approvals(
    request: Request,
    context: AuthContext,
    approvals: list[ApprovalView],
    *,
    error: str | None = None,
    notice: str | None = None,
) -> HTMLResponse:
    return render(
        request,
        "partials/approval_table.html",
        context={
            "approvals": approvals,
            "principal": context.principal,
            "csrf_token": context.csrf_token,
            "approval_error": error,
            "approval_notice": notice,
        },
    )


@router.get("/api/approvals", summary="Pending approvals")
async def list_approvals(
    request: Request,
    context: AuthContext = Depends(require_roles("operator", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> Any:
    """List open tickets. htmx receives the polling partial instead of JSON."""
    approvals = await list_pending(
        session,
        viewer_id=context.actor_id,
        viewer_roles=context.principal.roles,
        limit=get_settings().approval_page_size,
    )
    if is_htmx(request):
        return _render_approvals(request, context, approvals)
    return {
        "approvals": [ApprovalOut.from_view(view) for view in approvals],
        "count": len(approvals),
    }


@router.post("/api/approvals/{ticket_id}/action", summary="Approve or reject a ticket")
async def decide_approval(
    ticket_id: uuid.UUID,
    request: Request,
    action: str = Form(..., max_length=16),
    reason: str | None = Form(default=None, max_length=1024),
    context: AuthContext = Depends(require_csrf),
    _authorized: AuthContext = Depends(require_roles("operator", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> Any:
    """Decide one ticket. The row lock and DB constraint back up the checks here."""
    try:
        decision = parse_action(action)
        ticket = await decide_ticket(
            session,
            ticket_id=ticket_id,
            actor_id=context.actor_id,
            actor_roles=context.principal.roles,
            action=decision,
            reason=reason,
        )
        if decision == "approve":
            # Commit before enqueueing: the worker must never observe an
            # APPROVED ticket that the database has not durably stored yet.
            await session.commit()
            await enqueue_tool_resume(str(ticket.ticket_id))
    except ApprovalDecisionError as exc:
        if is_htmx(request):
            approvals = await list_pending(
                session,
                viewer_id=context.actor_id,
                viewer_roles=context.principal.roles,
                limit=get_settings().approval_page_size,
            )
            return _render_approvals(request, context, approvals, error=str(exc))
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    if is_htmx(request):
        approvals = await list_pending(
            session,
            viewer_id=context.actor_id,
            viewer_roles=context.principal.roles,
            limit=get_settings().approval_page_size,
        )
        return _render_approvals(
            request,
            context,
            approvals,
            notice=f"Ticket {str(ticket.ticket_id)[:8]} {ticket.status.value}.",
        )

    return {
        "ticket_id": str(ticket.ticket_id),
        "status": ticket.status.value,
        "approver_id": ticket.approver_id,
        "decided_at": utc_isoformat(ticket.decided_at) if ticket.decided_at else None,
    }
