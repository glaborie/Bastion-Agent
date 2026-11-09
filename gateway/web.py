"""Small HTTP helpers shared by the HTML-facing routes."""

from __future__ import annotations

from fastapi import Request


def is_htmx(request: Request) -> bool:
    """True when htmx issued the request (it sets ``HX-Request: true``)."""
    return request.headers.get("hx-request", "").strip().lower() == "true"
