"""Handoff notification policy, executed under Node (IDEA-069, ADR-022).

``gateway/dashboard/static/handoffs.js`` is the browser channel for the operator
handoff queue. Its policy is pinned here by running the shipped file against a
stub ``document``, ``sessionStorage`` and ``Notification``: one summary when the
page opens with a queue, silent when it opens empty, and one notification per
handoff queued while the tab stays open.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "handoffs_harness.js"
SCRIPT = ROOT / "gateway" / "dashboard" / "static" / "handoffs.js"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


def _run(scenario: str) -> dict[str, Any]:
    completed = subprocess.run(
        [str(NODE), str(HARNESS), str(SCRIPT), scenario],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )
    return json.loads(completed.stdout)


def test_first_load_summarises_the_queue_once() -> None:
    result = _run("open_with_queue")
    calls = result["calls"]

    assert result["firstLoad"] == 1, "a queue that was already waiting is one summary"
    summary = calls[0]
    assert summary["tag"] == "bastion-handoff-queue"
    assert "2 waiting" in summary["body"]
    assert "frustrated" in summary["body"]
    assert "conv-new" in summary["body"]
    assert "conv-old" not in summary["body"], "the summary names the newest id only"

    assert result["afterRepeatPoll"] == 1, "repeat polls over the same rows stay silent"
    assert result["afterReload"] == 1, "an acknowledged queue does not summarise again"


def test_empty_first_poll_is_silent_and_a_later_handoff_notifies() -> None:
    result = _run("open_empty_then_queue")
    calls = result["calls"]

    assert result["firstLoad"] == 0, "opening with an empty queue raises nothing"
    assert len(calls) == 1, "a handoff queued while the tab is open notifies individually"
    assert calls[0]["tag"] == "bastion-handoff-conv-late"
    assert "conv-late" in calls[0]["body"]
