"""FastAPI application entrypoint for the Bastion-Agent gateway.

Milestone 1 wires the health probes and the database lifecycle. Authentication,
the HTMX Command Control Center and the chat API are added by later milestones.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from db.session import dispose_engine, init_models
from gateway.routers import health
from logging_setup import configure_logging
from settings import get_settings
from telemetry import configure_tracing, instrument_app, shutdown_tracing

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Boot the persistence layer and tear it down cleanly."""
    configure_logging(get_settings().log_level)
    logger.info(
        "Starting Bastion-Agent gateway",
        extra={
            "environment": get_settings().environment,
            "database_url": get_settings().redacted_database_url,
        },
    )
    await init_models()
    try:
        yield
    finally:
        shutdown_tracing()
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
    )
    app.include_router(health.router)

    configure_tracing(settings)
    instrument_app(app)
    return app


app = create_app()
