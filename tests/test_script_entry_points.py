"""Entry points must start when the interpreter strips docstrings (IDEA-043).

``python -OO`` drops ``__doc__``, and mypy special-cases it as ``str``, so a
script that slices its own docstring for an ``ArgumentParser`` description works
in every gate and raises ``AttributeError`` in an optimised deployment.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

STRIPPED_DOCSTRING_SCRIPTS = (
    "check_classifier_dispatch.py",
    "demo_classifier.py",
    "benchmark_classifier_goldens.py",
)


@pytest.mark.parametrize("script", STRIPPED_DOCSTRING_SCRIPTS)
def test_a_script_prints_usage_when_the_docstring_is_stripped(script: str) -> None:
    result = subprocess.run(
        [sys.executable, "-OO", str(SCRIPTS / script), "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout


def test_no_script_slices_a_docstring_the_interpreter_may_strip() -> None:
    """Catch a fourth site: the fallback has to be a literal, not ``__doc__``."""
    offenders = sorted(
        path.name
        for path in SCRIPTS.glob("*.py")
        if "__doc__.splitlines" in path.read_text(encoding="utf-8")
    )

    assert offenders == []
