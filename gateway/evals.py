"""Reader for the latest DeepEval run summary (ADR-006).

Milestone 6's harness writes a small, immutable JSON report after each run. The
dashboard must never invent a green status: a missing file, a malformed report or
a report older than :data:`STALE_AFTER` is surfaced as such.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

logger = logging.getLogger(__name__)

EVAL_REPORT_MAX_BYTES = 1_048_576
STALE_AFTER = timedelta(hours=24)


class EvalRunSummary(BaseModel):
    """Schema of ``artifacts/evals/latest.json``."""

    model_config = ConfigDict(extra="ignore")

    run_id: str = Field(min_length=1, max_length=128)
    started_at: datetime
    finished_at: datetime
    total: int = Field(ge=0)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    metrics: dict[str, float] = Field(default_factory=dict)
    git_sha: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _counts_are_consistent(self) -> EvalRunSummary:
        if self.passed + self.failed != self.total:
            raise ValueError("passed + failed must equal total")
        if self.finished_at < self.started_at:
            raise ValueError("finished_at precedes started_at")
        return self

    @property
    def status(self) -> Literal["passed", "failed"]:
        return "passed" if self.failed == 0 else "failed"

    @property
    def pass_rate(self) -> float:
        return 1.0 if self.total == 0 else self.passed / self.total


@dataclass(frozen=True, slots=True)
class EvalReport:
    """Renderable view of the latest run (or of why there is none)."""

    available: bool
    summary: EvalRunSummary | None = None
    error: str | None = None
    modified_at: datetime | None = None

    @property
    def stale(self) -> bool:
        if self.modified_at is None:
            return True
        return datetime.now(UTC) - self.modified_at > STALE_AFTER


_cache: dict[str, tuple[int, int, EvalReport]] = {}


def load_latest_report(path_setting: str, *, root: Path | None = None) -> EvalReport:
    """Load and validate the newest report, cached by mtime and size."""
    path = _resolve(path_setting, root or Path.cwd())
    try:
        stat = path.stat()
    except FileNotFoundError:
        return EvalReport(available=False, error="no evaluation run recorded yet")
    except OSError as exc:
        logger.warning("Could not stat the eval report", extra={"error": str(exc)})
        return EvalReport(available=False, error="evaluation report is not readable")

    if stat.st_size > EVAL_REPORT_MAX_BYTES:
        return EvalReport(available=False, error="evaluation report is unexpectedly large")

    cache_key = str(path)
    cached = _cache.get(cache_key)
    if cached is not None and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
        return cached[2]

    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
        summary = EvalRunSummary.model_validate(raw)
    except (OSError, ValueError, ValidationError) as exc:
        logger.warning("Invalid eval report", extra={"error": str(exc)})
        report = EvalReport(available=False, error="evaluation report is invalid")
        _cache[cache_key] = (stat.st_mtime_ns, stat.st_size, report)
        return report

    report = EvalReport(
        available=True,
        summary=summary,
        modified_at=datetime.fromtimestamp(stat.st_mtime, tz=UTC),
    )
    _cache[cache_key] = (stat.st_mtime_ns, stat.st_size, report)
    return report


def _resolve(path_setting: str, root: Path) -> Path:
    path = Path(path_setting).expanduser()
    return path if path.is_absolute() else root / path
