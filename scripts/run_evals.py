#!/usr/bin/env python3
"""Run the zero-tolerance evaluation gates and publish the run summary.

    uv run python scripts/run_evals.py
    uv run python scripts/run_evals.py --json
    uv run python scripts/run_evals.py --report /tmp/latest.json
    uv run python scripts/run_evals.py -k test_dlp_evals

The script runs the three ADR-006 gates in-process, maps each module to its
metric, and writes ``artifacts/evals/latest.json`` atomically. The gateway reads
that file through ``GET /api/evals/latest``; nothing else may write it. Every run
also writes ``latest-junit.xml`` beside the summary, atomically and world
readable, with one testcase per node id — outcome and skip reason — so the
``run_id`` plus that file explains which tests produced the summary.

Arguments the script does not know (``-k``, ``-v``, ``-x``, ``--tb=short`` and the
like) are forwarded to pytest unchanged. A run the caller narrows scores only the
gates it touched; a narrowing that touches none is red, and an argument-free run
still scores all three.

Semantics, deliberately strict:

* A gate metric is ``1.0`` only when at least one test executed and none failed.
* A skipped-only gate scores ``0.0`` and contributes a synthetic failure: an
  unverified gate is not a pass. On a host without the ONNX graphs the
  classifier routing test skips, so this report is red until the models are
  present — which is the honest result.
* The one exception is an explicit dispatch verdict (ADR-011): a host whose int8
  kernels do not reproduce the calibration verdicts has its classifier gate
  skipped *and* exempted, published under ``exempt_gates``. A failed test is
  never exempted.
* The exit code is non-zero when pytest fails or any summary count is non-zero.

The file is replaced with :func:`os.replace`, so a reader never observes a
partially written report.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal

import pytest

#: Module -> metric name published to the dashboard.
GATES: Final[dict[str, str]] = {
    "tests/test_dlp_evals.py": "DLPRedactionMetric",
    "tests/test_egress_evals.py": "EgressCanaryMetric",
    "tests/test_classifier_evals.py": "ClassifierGoldenGate",
}

Outcome = Literal["passed", "failed", "skipped"]
DEFAULT_REPORT: Final[Path] = Path("artifacts/evals/latest.json")
JUNIT_NAME: Final[str] = "latest-junit.xml"


@dataclass(eq=False)
class _Collector:
    """Minimal pytest plugin: final outcome per node id.

    ``eq=False`` keeps the default identity hash: pytest stores plugins in a
    dictionary, so a value-equal dataclass would be unhashable.
    """

    outcomes: dict[str, Outcome] = field(default_factory=dict)

    def pytest_runtest_logreport(self, report: Any) -> None:
        node = report.nodeid
        if self.outcomes.get(node) == "failed":
            return
        if report.failed:
            self.outcomes[node] = "failed"
        elif report.skipped and self.outcomes.get(node) != "passed":
            # Covers both ``skipif`` (setup) and ``pytest.skip()`` in the body
            # (call), which is how the dispatch exemption skips.
            self.outcomes[node] = "skipped"
        elif report.when == "call" and report.passed:
            self.outcomes[node] = "passed"


@dataclass(frozen=True, slots=True)
class RunSummary:
    run_id: str
    started_at: datetime
    finished_at: datetime
    total: int
    passed: int
    failed: int
    metrics: dict[str, float]
    git_sha: str | None
    #: metric -> verdict for gates the host exempted (ADR-011); empty otherwise.
    exempt_gates: dict[str, str] = field(default_factory=dict)

    def as_report(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "metrics": self.metrics,
            "git_sha": self.git_sha,
            "exempt_gates": self.exempt_gates,
        }


def _module_of(node_id: str) -> str:
    return node_id.split("::", 1)[0]


def scoped_gates(outcomes: Mapping[str, Outcome], *, narrowed: bool) -> dict[str, str]:
    """Gates this run must score.

    An argument-free run scores every gate, so one that produced no evidence
    stays a synthetic failure. A caller-narrowed run scores only the gates that
    produced an outcome; a narrowing that touches no gate leaves the mapping
    empty, which :func:`summarise` still reports as a red run.
    """
    if not narrowed:
        return dict(GATES)
    ran = {_module_of(node_id) for node_id in outcomes}
    return {module: metric for module, metric in GATES.items() if module in ran}


def summarise(
    outcomes: Mapping[str, Outcome],
    *,
    started_at: datetime,
    finished_at: datetime,
    git_sha: str | None,
    run_id: str | None = None,
    gates: Mapping[str, str] | None = None,
    exempt_gates: Mapping[str, str] | None = None,
) -> RunSummary:
    """Turn per-test outcomes into the published summary.

    ``failed`` includes one synthetic failure per gate that did not execute a
    single test, so an all-skipped run cannot report a green status — unless the
    host's dispatch verdict exempts that gate, in which case the exemption is
    published instead. A gate with a failed test is never exempted.
    """
    resolved_gates = GATES if gates is None else gates
    resolved_exempt = dict(exempt_gates or {})
    per_gate: dict[str, list[Outcome]] = {module: [] for module in resolved_gates}
    for node_id, outcome in outcomes.items():
        module = _module_of(node_id)
        if module in per_gate:
            per_gate[module].append(outcome)

    passed = sum(1 for outcome in outcomes.values() if outcome == "passed")
    failed = sum(1 for outcome in outcomes.values() if outcome == "failed")
    skipped = sum(1 for outcome in outcomes.values() if outcome == "skipped")

    metrics: dict[str, float] = {}
    applied_exemptions: dict[str, str] = {}
    unverified_gates = 0
    for module, metric in resolved_gates.items():
        results = per_gate[module]
        executed = [outcome for outcome in results if outcome != "skipped"]
        # An exemption is only recorded when the flag actually took effect (a
        # test skipped) and nothing in the gate failed. The classifier module
        # keeps model-free tests, so "all skipped" is not the usual shape.
        exempted = metric in resolved_exempt and "skipped" in results and "failed" not in results
        if exempted:
            applied_exemptions[metric] = resolved_exempt[metric]
        ok = bool(executed) and all(outcome == "passed" for outcome in executed)
        metrics[metric] = 1.0 if ok or exempted else 0.0
        if not executed and not exempted:
            # No test ran for this gate: an unverified gate is not a pass.
            unverified_gates += 1
    if skipped:
        metrics["skipped_tests"] = float(skipped)

    failed += unverified_gates
    total = passed + failed
    if total == 0:
        # Nothing ran at all: report a red run rather than a vacuous pass.
        total = 1
        failed = 1

    return RunSummary(
        run_id=run_id or uuid.uuid4().hex,
        started_at=started_at,
        finished_at=finished_at,
        total=total,
        passed=passed,
        failed=failed,
        metrics=metrics,
        git_sha=git_sha,
        exempt_gates=applied_exemptions,
    )


def write_report(path: Path, summary: RunSummary) -> Path:
    """Atomically replace the report so readers never see a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(summary.as_report(), indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=".latest-", suffix=".json", delete=False
    ) as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    # The gateway reads the report from a read-only mount under a different uid;
    # the summary contains no secrets, so make it explicitly world-readable.
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)
    return path


def write_evidence(source: Path, destination: Path) -> Path:
    """Move pytest's JUnit file next to the summary, world-readable and atomic."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(source, 0o644)
    os.replace(source, destination)
    return destination


def git_sha() -> str | None:
    """Return the current commit, or ``None`` outside a repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607 - resolved from PATH by design
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = result.stdout.strip()
    return sha if result.returncode == 0 and len(sha) == 40 else None


def _pytest_args(extra: Iterable[str], junit: Path) -> list[str]:
    return ["-q", "-p", "no:cacheprovider", *GATES, f"--junitxml={junit}", *extra]


def main(argv: list[str] | None = None) -> int:
    description = __doc__ or (
        "Run the zero-tolerance evaluation gates and publish the run summary."
    )
    parser = argparse.ArgumentParser(description=description.splitlines()[0])
    parser.add_argument(
        "--report",
        default=os.getenv("EVAL_REPORT_PATH", str(DEFAULT_REPORT)),
        help="destination JSON summary (default: artifacts/evals/latest.json)",
    )
    parser.add_argument(
        "--dispatch-verdict",
        choices=("reference", "dispatch_anomaly", "unknown"),
        default=os.getenv("CLASSIFIER_DISPATCH_VERDICT", "reference"),
        help="host verdict from scripts/check_classifier_dispatch.py",
    )
    parser.add_argument("--json", action="store_true", help="print the summary as JSON")
    # Unknown arguments are the pytest passthrough: a positional ``nargs="*"``
    # would steal the value of ``-k`` before the option was recognised.
    options, forwarded = parser.parse_known_args(argv)

    exempt: dict[str, str] = {}
    if options.dispatch_verdict == "dispatch_anomaly":
        # The gate tests read this to skip their assertions; the summary then
        # records the exemption instead of the skipped-only synthetic failure.
        os.environ["CLASSIFIER_DISPATCH_VERDICT"] = "dispatch_anomaly"
        exempt = {"ClassifierGoldenGate": "dispatch_anomaly"}

    report_path = Path(options.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    # pytest writes its JUnit file in one pass; a sibling temp path lets the
    # finished evidence replace the published one atomically.
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=report_path.parent,
        prefix=".latest-",
        suffix=".xml",
        delete=False,
    ) as handle:
        junit_temporary = Path(handle.name)

    collector = _Collector()
    started = datetime.now(UTC)
    exit_code = int(pytest.main(_pytest_args(forwarded, junit_temporary), plugins=[collector]))
    finished = datetime.now(UTC)

    if junit_temporary.stat().st_size == 0:
        raise SystemExit("run-evals: pytest wrote no JUnit evidence")

    summary = summarise(
        collector.outcomes,
        started_at=started,
        finished_at=finished,
        git_sha=git_sha(),
        gates=scoped_gates(collector.outcomes, narrowed=bool(forwarded)),
        exempt_gates=exempt,
    )
    evidence = write_evidence(junit_temporary, report_path.with_name(JUNIT_NAME))
    path = write_report(report_path, summary)

    if options.json:
        print(json.dumps(summary.as_report(), indent=2, sort_keys=True))
    else:
        print(f"evals: {summary.passed}/{summary.total} passed, {summary.failed} failed -> {path}")
        print(f"  evidence: {evidence}")
        for metric, score in sorted(summary.metrics.items()):
            print(f"  {metric:<24} {score:.3f}")
        for metric, verdict in sorted(summary.exempt_gates.items()):
            print(f"  {metric:<24} exempt ({verdict})")

    ok = exit_code == 0 and summary.failed == 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
