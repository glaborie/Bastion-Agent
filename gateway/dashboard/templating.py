"""Jinja2 environment shared by the dashboard and the HTML/HTMX API routes."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

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


templates.env.filters["short_hash"] = _short_hash
templates.env.filters["utc_ts"] = _utc_timestamp
templates.env.globals["app_title"] = "Bastion-Agent"


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


def render_error(
    request: Request,
    *,
    title: str,
    detail: str,
    status_code: int,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    return render(
        request,
        "error.html",
        context={
            "title": title,
            "detail": detail,
            "principal": None,
            "csrf_token": None,
        },
        status_code=status_code,
        headers=headers,
    )
