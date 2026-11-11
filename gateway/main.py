"""FastAPI application entrypoint for the Bastion-Agent gateway.

Wires authentication, the Command Control Center, the approval queue and the
audit ledger around the health probes from Milestone 1.
"""

from __future__ import annotations

import logging
import urllib.parse
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exception_handlers import http_exception_handler as default_http_exception_handler
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from agent.routing.client import close_model_router
from agent.tools.decorator import verify_registry
from db.session import dispose_engine, init_models
from gateway.auth.rbac import shutdown_auth
from gateway.auth.session import safe_next_path
from gateway.dashboard.demo import router as demo_router
from gateway.dashboard.routes import router as dashboard_router
from gateway.dashboard.templating import render_error
from gateway.queue import close_arq_pool
from gateway.routers import approval_ws, approvals, audit, auth, chat, evals, health
from gateway.web import is_htmx
from logging_setup import configure_logging
from settings import get_settings
from telemetry import configure_tracing, instrument_app, shutdown_tracing

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "dashboard" / "static"

_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "base-uri 'none'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "script-src 'self'; "
    # htmx toggles inline style properties while swapping fragments; scripts stay
    # strictly first-party and no inline <script> is allowed.
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'"
)

_NO_STORE_PREFIXES = ("/dashboard", "/api", "/auth")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Boot the persistence layer and tear everything down cleanly."""
    configure_logging(get_settings().log_level)
    logger.info(
        "Starting Bastion-Agent gateway",
        extra={
            "environment": get_settings().environment,
            "database_url": get_settings().redacted_database_url,
        },
    )
    # ADR-009 Gate 1: a registered tool that the catalog has not approved stops
    # the gateway instead of being silently reachable. The check runs before the
    # database so a misconfigured deployment fails fast.
    verify_registry()
    await init_models()
    try:
        yield
    finally:
        shutdown_tracing()
        await close_arq_pool()
        await close_model_router()
        await shutdown_auth()
        await dispose_engine()
        logger.info("Bastion-Agent gateway stopped")


def create_app() -> FastAPI:
    """Application factory (keeps ``--reload`` and tests predictable)."""
    settings = get_settings()
    app = FastAPI(
        title="Bastion-Agent Gateway",
        version="0.1.0",
        description=(
            "High-assurance, zero-trust AI agent control plane: deterministic DLP, "
            "confidentiality routing, four-eyes tool approval and a hash-chained "
            "audit ledger."
        ),
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url=None,
        lifespan=lifespan,
        openapi_tags=[
            {"name": "health", "description": "Liveness and readiness probes."},
            {"name": "auth", "description": "OIDC login, session and identity endpoints."},
            {"name": "approvals", "description": "Four-eyes approval queue."},
            {"name": "audit", "description": "Hash-chained audit ledger."},
            {"name": "chat", "description": "Guarded chat completion with DLP and egress."},
            {"name": "evals", "description": "DeepEval regression health."},
        ],
    )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(approvals.router)
    app.include_router(approval_ws.router)
    app.include_router(audit.router)
    app.include_router(chat.router)
    app.include_router(evals.router)
    app.include_router(dashboard_router)
    app.include_router(demo_router)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", _CONTENT_SECURITY_POLICY)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        if request.url.path.startswith(_NO_STORE_PREFIXES):
            response.headers.setdefault("Cache-Control", "no-store")
        if request.url.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> Response:
        path = request.url.path
        if exc.status_code == 401 and path == "/auth/logout":
            # The session already expired; clearing the cookie is the useful
            # outcome, and the operator lands back on a public page.
            response = RedirectResponse("/", status_code=303)
            response.delete_cookie(get_settings().session_cookie_name, path="/")
            return response
        if exc.status_code == 401:
            target = path + (f"?{request.url.query}" if request.url.query else "")
            if is_htmx(request):
                # A partial endpoint must not become the post-login destination;
                # send the browser back to the page that hosts the partial.
                next_path = "/dashboard" if path.startswith("/api/") else target
                login_url = "/auth/login?next=" + urllib.parse.quote(
                    safe_next_path(next_path), safe=""
                )
                # A 3xx would be followed by XHR and render the login page into
                # the fragment; ask htmx to navigate instead.
                return Response(status_code=401, headers={"HX-Redirect": login_url})
            if path.startswith("/dashboard") or path == "/":
                login_url = "/auth/login?next=" + urllib.parse.quote(
                    safe_next_path(target), safe=""
                )
                return RedirectResponse(login_url, status_code=303)
        if exc.status_code == 403 and path.startswith("/dashboard"):
            return render_error(
                request,
                title="Not authorized",
                detail="This dashboard requires the operator or admin role.",
                status_code=403,
            )
        if exc.status_code == 429 and (path.startswith("/dashboard") or is_htmx(request)):
            # A polling fragment that renders the JSON detail is unreadable in
            # the dashboard; show the same page an operator can act on, with the
            # Retry-After the limiter produced.
            headers = dict(exc.headers or {})
            retry_after = headers.get("Retry-After", "60")
            return render_error(
                request,
                title="Too many requests",
                detail=(
                    "This account has used its request budget for the dashboard. "
                    f"Try again in {retry_after} seconds."
                ),
                status_code=429,
                headers=headers,
            )
        return await default_http_exception_handler(request, exc)

    configure_tracing(settings)
    instrument_app(app)
    return app


app = create_app()
