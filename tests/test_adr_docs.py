"""Keep the ADR set and its index consistent (see docs/adr/ADR-Index.md)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_adr_set_is_valid() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_adrs.py")],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK:" in result.stdout
