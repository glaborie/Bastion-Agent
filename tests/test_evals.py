"""Evaluation-report reader tests (ADR-006)."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from gateway.evals import EvalRunSummary, load_latest_report


def _payload(**overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    base: dict[str, object] = {
        "run_id": "run-1",
        "started_at": (now - timedelta(minutes=2)).isoformat(),
        "finished_at": now.isoformat(),
        "total": 27,
        "passed": 27,
        "failed": 0,
        "metrics": {"DLPRedactionMetric": 1.0, "EgressCanaryMetric": 1.0},
        "git_sha": "abc123",
    }
    base.update(overrides)
    return base


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_missing_report_is_reported_not_invented(tmp_path: Path) -> None:
    report = load_latest_report(str(tmp_path / "latest.json"))
    assert report.available is False
    assert report.summary is None
    assert "no evaluation run" in (report.error or "")
    assert report.stale is True


def test_valid_report_is_parsed(tmp_path: Path) -> None:
    path = _write(tmp_path / "latest.json", _payload())
    report = load_latest_report(str(path))
    assert report.available is True
    assert report.summary is not None
    assert report.summary.status == "passed"
    assert report.summary.pass_rate == 1.0
    assert report.error is None
    assert report.stale is False


def test_failed_run_is_not_green(tmp_path: Path) -> None:
    path = _write(tmp_path / "latest.json", _payload(passed=26, failed=1))
    report = load_latest_report(str(path))
    assert report.available is True
    assert report.summary is not None
    assert report.summary.status == "failed"
    assert report.summary.pass_rate == 26 / 27


def test_inconsistent_counts_are_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path / "latest.json", _payload(total=10, passed=9, failed=4))
    report = load_latest_report(str(path))
    assert report.available is False
    assert report.error == "evaluation report is invalid"


def test_malformed_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "latest.json"
    path.write_text("{not json", encoding="utf-8")
    report = load_latest_report(str(path))
    assert report.available is False
    assert report.error == "evaluation report is invalid"


def test_oversized_report_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "latest.json"
    path.write_bytes(b"{" + b" " * (1_048_576 + 1) + b"}")
    report = load_latest_report(str(path))
    assert report.available is False
    assert "large" in (report.error or "")


def test_stale_report_is_flagged(tmp_path: Path) -> None:
    path = _write(tmp_path / "latest.json", _payload())
    two_days_ago = time.time() - 2 * 24 * 3600
    os.utime(path, (two_days_ago, two_days_ago))
    report = load_latest_report(str(path))
    assert report.available is True
    assert report.stale is True


def test_summary_requires_temporal_order() -> None:
    payload = _payload(
        started_at=datetime.now(UTC).isoformat(),
        finished_at=(datetime.now(UTC) - timedelta(hours=1)).isoformat(),
    )
    try:
        EvalRunSummary.model_validate(payload)
    except ValueError:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("finished_at before started_at must be rejected")
