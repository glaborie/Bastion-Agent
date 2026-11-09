"""Liveness and readiness probes consumed by Docker, load balancers and CI."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from db.session import ping
from settings import get_settings

router = APIRouter(tags=["health"])


class LivenessResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str
    environment: str
    version: str = "0.1.0"


class ReadinessResponse(BaseModel):
    status: Literal["ready", "degraded"]
    checks: dict[str, bool]


@router.get("/health", response_model=LivenessResponse, summary="Liveness probe")
async def liveness() -> LivenessResponse:
    """Cheap check: the process is up and serving requests."""
    settings = get_settings()
    return LivenessResponse(
        service=settings.app_name,
        environment=settings.environment,
    )


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    summary="Readiness probe",
    responses={503: {"description": "At least one dependency is unavailable"}},
)
async def readiness() -> JSONResponse:
    """Deep check: dependencies required to serve traffic are reachable."""
    checks = {"database": await ping()}
    healthy = all(checks.values())
    payload = ReadinessResponse(
        status="ready" if healthy else "degraded",
        checks=checks,
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
        content=payload.model_dump(),
    )
