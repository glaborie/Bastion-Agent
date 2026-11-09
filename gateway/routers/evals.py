"""Evaluation-health API backing the dashboard card (ADR-006)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from gateway.auth.rbac import AuthContext, require_roles
from gateway.dashboard.templating import render
from gateway.evals import EvalReport, load_latest_report
from gateway.web import is_htmx
from settings import get_settings

router = APIRouter(tags=["evals"])


@router.get("/api/evals/latest", summary="Latest DeepEval run summary")
async def latest_report(
    request: Request,
    context: AuthContext = Depends(require_roles("operator", "admin")),
) -> Any:
    report = load_latest_report(get_settings().eval_report_path)
    if is_htmx(request):
        return render(
            request,
            "partials/eval_status.html",
            context={
                "report": report,
                "principal": context.principal,
                "csrf_token": context.csrf_token,
            },
        )
    return _serialise(report)


def _serialise(report: EvalReport) -> dict[str, Any]:
    return {
        "available": report.available,
        "error": report.error,
        "stale": report.stale,
        "modified_at": report.modified_at.isoformat() if report.modified_at else None,
        "summary": report.summary.model_dump(mode="json") if report.summary else None,
    }
