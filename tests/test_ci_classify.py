"""Contract tests for the CI diff classifier used by .github/workflows/ci.yml."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci_classify_changes.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def classify(*paths: str) -> dict[str, str]:
    """Run the classifier over a synthetic diff, as the workflow pipes one in."""
    result = subprocess.run(
        [str(SCRIPT)],
        input="\n".join(paths),
        text=True,
        capture_output=True,
        check=True,
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


def test_a_root_shell_script_skips_the_suite_and_osv() -> None:
    outputs = classify("run_opencode.sh")

    assert outputs["tests"] == "false"
    assert outputs["docs_only"] == "false"
    assert outputs["osv"] == "false"


def test_docs_only_skips_both_documented_suites() -> None:
    outputs = classify("README.md", "wiki/Sidebar.md", "docs/img/dashboard.png")

    assert outputs["docs_only"] == "true"
    assert outputs["tests"] == "false"


def test_a_python_change_runs_the_suite() -> None:
    assert classify("agent/dlp/presidio.py")["tests"] == "true"


def test_a_config_change_runs_the_suite() -> None:
    # docs/ is not part of the docs-only rule: the tool catalogue is validated.
    assert classify("docs/tools/v1.json")["tests"] == "true"


def test_a_mixed_diff_runs_the_suite() -> None:
    assert classify("README.md", "run_opencode.sh", "db/models.py")["tests"] == "true"


def test_an_empty_diff_runs_the_suite() -> None:
    outputs = classify()

    assert outputs["tests"] == "true"
    assert outputs["docs_only"] == "false"
    assert outputs["osv"] == "true"


def test_osv_runs_for_audit_inputs_and_gate_changes() -> None:
    for path in (
        "uv.lock",
        "pyproject.toml",
        "scripts/update_threat_intel.py",
        "scripts/ci_classify_changes.sh",
        "tests/test_threat_intel.py",
        ".github/workflows/ci.yml",
    ):
        assert classify(path)["osv"] == "true", path
    assert classify("gateway/main.py")["osv"] == "false"


def test_deletions_and_both_sides_of_renames_are_classified(tmp_path: Path) -> None:
    git_path = shutil.which("git")
    assert git_path is not None

    def git(*args: str) -> str:
        return subprocess.run(
            [git_path, *args], cwd=tmp_path, text=True, capture_output=True, check=True
        ).stdout

    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "CI test")
    (tmp_path / "uv.lock").write_text("locked", encoding="utf-8")
    git("add", "uv.lock")
    git("commit", "-qm", "base")
    git("mv", "uv.lock", "notes.md")
    paths = git("diff", "--cached", "--no-renames", "--name-only", "--diff-filter=ACDMT")

    assert classify(*paths.splitlines())["osv"] == "true"
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "git diff --no-renames --name-only --diff-filter=ACDMT" in workflow


def test_evals_and_scan_keep_their_own_filters() -> None:
    assert classify("agent/routing/classifier.py")["evals"] == "true"
    assert classify("tests/data/goldens.jsonl")["evals"] == "true"
    assert classify("trivy.yaml")["scan"] == "true"
    assert classify("scripts/ci_classify_changes.sh")["scan"] == "true"
    assert classify("README.md")["scan"] == "false"
    assert classify("README.md")["evals"] == "false"


def test_every_shell_script_the_workflow_runs_still_gates_the_suite() -> None:
    """The root-level exemption is only safe while CI executes no such script."""
    text = WORKFLOW.read_text(encoding="utf-8")
    referenced = {match.group(1) for match in re.finditer(r"([\w./-]+\.sh)\b", text)}
    executed = sorted(path for path in referenced if "/" in path and (ROOT / path).is_file())

    assert executed, "ci.yml names no shell script any more; update this test"
    for path in executed:
        assert classify(path)["tests"] == "true", path


def test_the_workflow_calls_the_classifier_instead_of_inlining_it() -> None:
    assert "ci_classify_changes.sh" in WORKFLOW.read_text(encoding="utf-8")
