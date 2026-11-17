"""Jinja2 environment shared by the dashboard and the HTML/HTMX API routes."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gateway.auth.rbac import session_principal
from gateway.auth.roles import CHAT_ROLES, READ_ROLES, WRITE_ROLES, any_satisfied
from gateway.dashboard.theme import theme_from_request

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def _short_hash(value: object, length: int = 12) -> str:
    text = str(value) if value is not None else ""
    return text if len(text) <= length else f"{text[:length]}…"


def _utc_timestamp(value: object) -> str:
    if isinstance(value, datetime):
        moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%SZ")
    return "—"


def _has_role(principal: object, roles: tuple[str, ...]) -> bool:
    """Template-side check against the same role sets the routes enforce."""
    granted: frozenset[str] = getattr(principal, "roles", frozenset())
    return bool(granted) and any_satisfied(granted, roles)


templates.env.filters["short_hash"] = _short_hash
templates.env.filters["utc_ts"] = _utc_timestamp
templates.env.globals["app_title"] = "Bastion-Agent"
#: The role sets are the routes' own, so a link and the page behind it cannot
#: disagree (ADR-007 decision 9).
templates.env.globals["has_role"] = _has_role
templates.env.globals["READ_ROLES"] = READ_ROLES
templates.env.globals["WRITE_ROLES"] = WRITE_ROLES
templates.env.globals["CHAT_ROLES"] = CHAT_ROLES


def render(
    request: Request,
    template_name: str,
    *,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    """Render a template with the request already wired into the context."""
    payload: dict[str, Any] = {"request": request, "theme": theme_from_request(request)}
    payload.update(context or {})
    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context=payload,
        status_code=status_code,
        headers=headers,
    )


async def render_error(
    request: Request,
    *,
    title: str,
    detail: str,
    status_code: int,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    """Render an error page with the caller's own header when there is one.

    A signed-in principal without the role the page needs used to land on a
    chrome-less page with no Sign out; resolving the cookie here keeps the
    operator bar, and the template offers Sign out instead of a dead link back
    to a route that will refuse them again.
    """
    principal, csrf_token = await session_principal(request)
    authorized = principal is not None and any_satisfied(principal.roles, READ_ROLES)
    return render(
        request,
        "error.html",
        context={
            "title": title,
            "detail": detail,
            "principal": principal,
            "csrf_token": csrf_token,
            "dashboard_link": authorized or principal is None,
        },
        status_code=status_code,
        headers=headers,
    )
