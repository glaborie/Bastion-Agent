"""Eval-run summary and atomic report writer tests (ADR-006, Milestone 6)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from stat import S_IMODE

from gateway.evals import EvalRunSummary
from scripts.run_evals import GATES, summarise, write_report

STARTED = datetime(2026, 11, 10, 9, 0, tzinfo=UTC)
FINISHED = STARTED + timedelta(seconds=42)


def _summary(outcomes: dict[str, str]):  # type: ignore[no-untyped-def]
    return summarise(
        outcomes,  # type: ignore[arg-type]
        started_at=STARTED,
        finished_at=FINISHED,
        git_sha="a" * 40,
        run_id="run-fixed",
    )


def test_all_gates_passing_publishes_ones() -> None:
    summary = _summary(
        {
            "tests/test_dlp_evals.py::test_a": "passed",
            "tests/test_dlp_evals.py::test_b": "passed",
            "tests/test_egress_evals.py::test_c": "passed",
            "tests/test_classifier_evals.py::test_d": "passed",
        }
    )
    assert (summary.total, summary.passed, summary.failed) == (4, 4, 0)
    assert all(summary.metrics[metric] == 1.0 for metric in GATES.values())


def test_one_failed_test_fails_its_gate_and_the_run() -> None:
    summary = _summary(
        {
            "tests/test_dlp_evals.py::test_a": "passed",
            "tests/test_egress_evals.py::test_c": "passed",
            "tests/test_classifier_evals.py::test_d": "failed",
            "tests/test_classifier_evals.py::test_e": "passed",
        }
    )
    assert (summary.total, summary.passed, summary.failed) == (4, 3, 1)
    assert summary.metrics["ClassifierGoldenGate"] == 0.0
    assert summary.metrics["DLPRedactionMetric"] == 1.0


def test_an_all_skipped_gate_is_a_synthetic_failure() -> None:
    summary = _summary(
        {
            "tests/test_dlp_evals.py::test_a": "passed",
            "tests/test_egress_evals.py::test_c": "passed",
            "tests/test_classifier_evals.py::test_d": "skipped",
            "tests/test_classifier_evals.py::test_e": "skipped",
        }
    )
    assert summary.metrics["ClassifierGoldenGate"] == 0.0
    assert summary.metrics["skipped_tests"] == 2.0
    assert summary.failed == 1  # the synthetic failure for the unverified gate
    assert summary.passed + summary.failed == summary.total


def test_no_tests_at_all_is_red() -> None:
    summary = _summary({})
    assert summary.passed == 0
    assert summary.failed == len(GATES)  # one synthetic failure per unverified gate
    assert summary.total == summary.failed


def test_a_dispatch_anomaly_exempts_a_skipped_gate() -> None:
    summary = summarise(
        {
            "tests/test_dlp_evals.py::test_a": "passed",
            "tests/test_egress_evals.py::test_c": "passed",
            "tests/test_classifier_evals.py::test_d": "skipped",
        },
        started_at=STARTED,
        finished_at=FINISHED,
        git_sha="a" * 40,
        run_id="run-exempt",
        exempt_gates={"ClassifierGoldenGate": "dispatch_anomaly"},
    )
    assert summary.failed == 0
    assert summary.metrics["ClassifierGoldenGate"] == 1.0
    assert summary.exempt_gates == {"ClassifierGoldenGate": "dispatch_anomaly"}
    assert summary.as_report()["exempt_gates"] == {"ClassifierGoldenGate": "dispatch_anomaly"}
    assert EvalRunSummary.model_validate(summary.as_report()).status == "passed"


def test_a_mixed_gate_records_the_exemption() -> None:
    """The classifier module keeps model-free tests, so a pass and a skip mix.

    The exemption must still be published — otherwise the report shows a full
    green gate while the two ratio assertions never ran.
    """
    summary = summarise(
        {
            "tests/test_dlp_evals.py::test_a": "passed",
            "tests/test_egress_evals.py::test_c": "passed",
            "tests/test_classifier_evals.py::test_corpus": "passed",
            "tests/test_classifier_evals.py::test_golden": "skipped",
            "tests/test_classifier_evals.py::test_gaps": "skipped",
        },
        started_at=STARTED,
        finished_at=FINISHED,
        git_sha="a" * 40,
        run_id="run-mixed",
        exempt_gates={"ClassifierGoldenGate": "dispatch_anomaly"},
    )
    assert summary.failed == 0
    assert summary.exempt_gates == {"ClassifierGoldenGate": "dispatch_anomaly"}


def test_an_exemption_without_a_skip_is_not_recorded() -> None:
    """The flag alone is not evidence: something must have skipped for it."""
    summary = summarise(
        {
            "tests/test_dlp_evals.py::test_a": "passed",
            "tests/test_egress_evals.py::test_c": "passed",
            "tests/test_classifier_evals.py::test_d": "passed",
        },
        started_at=STARTED,
        finished_at=FINISHED,
        git_sha="a" * 40,
        run_id="run-ignored",
        exempt_gates={"ClassifierGoldenGate": "dispatch_anomaly"},
    )
    assert not summary.exempt_gates


def test_the_exemption_never_covers_a_failed_row() -> None:
    """A broken golden row fails the run even on a host that is exempted."""
    summary = summarise(
        {
            "tests/test_dlp_evals.py::test_a": "passed",
            "tests/test_egress_evals.py::test_c": "passed",
            "tests/test_classifier_evals.py::test_d": "failed",
            "tests/test_classifier_evals.py::test_e": "skipped",
        },
        started_at=STARTED,
        finished_at=FINISHED,
        git_sha="a" * 40,
        run_id="run-failed",
        exempt_gates={"ClassifierGoldenGate": "dispatch_anomaly"},
    )
    assert summary.failed == 1
    assert summary.metrics["ClassifierGoldenGate"] == 0.0
    assert not summary.exempt_gates


def test_report_is_valid_and_replaced_atomically(tmp_path: Path) -> None:
    summary = _summary({"tests/test_dlp_evals.py::test_a": "passed"})
    path = write_report(tmp_path / "nested" / "latest.json", summary)

    payload = path.read_text(encoding="utf-8")
    validated = EvalRunSummary.model_validate_json(payload)
    assert validated.run_id == "run-fixed"
    assert validated.passed + validated.failed == validated.total
    assert validated.git_sha == "a" * 40
    assert not list(path.parent.glob(".latest-*"))
    # The gateway reads this file as a different uid from a read-only mount.
    assert S_IMODE(path.stat().st_mode) == 0o644
