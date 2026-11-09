"""ARQ worker entrypoint.

Milestone 1 establishes the worker process lifecycle (configuration, schema
bootstrap, graceful shutdown). The guarded tool-execution state machine and the
four-eyes resumption callback are implemented in Milestone 4.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from arq.connections import RedisSettings

from db.session import dispose_engine, init_models
from logging_setup import configure_logging
from settings import get_settings

logger = logging.getLogger(__name__)


async def startup(ctx: dict[str, Any]) -> None:
    """Prepare the worker before it starts consuming jobs."""
    settings = get_settings()
    configure_logging(settings.log_level)
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


async def shutdown(ctx: dict[str, Any]) -> None:
    """Release resources when the worker receives a shutdown signal."""
    await dispose_engine()
    logger.info("Bastion-Agent worker stopped")


class WorkerSettings:
    """ARQ configuration consumed by ``arq agent.runtime.WorkerSettings``."""

    functions: ClassVar[list[Any]] = [worker_healthcheck]
    redis_settings: ClassVar[RedisSettings] = RedisSettings.from_dsn(get_settings().redis_url)
    queue_name: ClassVar[str] = "bastion:jobs"
    on_startup: ClassVar[Any] = startup
    on_shutdown: ClassVar[Any] = shutdown
    job_timeout: ClassVar[int] = 300
    max_tries: ClassVar[int] = 3
    keep_result: ClassVar[int] = 3600
