"""Verify that CI shards partition the collected suite without dropping tests."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def collect(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env.pop("PYTEST_ADDOPTS", None)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "scripts.pytest_ci_shard",
            "--collect-only",
            "-q",
            *args,
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_shards_cover_each_test_once(tmp_path: Path) -> None:
    (tmp_path / "test_sample.py").write_text(
        "\n".join(f"def test_{number}(): pass" for number in range(7)), encoding="utf-8"
    )
    results = [collect(tmp_path, f"--ci-shard={index}/2") for index in (1, 2)]
    assert all(result.returncode == 0 for result in results)
    shards = [
        {line for line in result.stdout.splitlines() if "::test_" in line} for result in results
    ]
    assert not shards[0] & shards[1]
    assert len(shards[0] | shards[1]) == 7


@pytest.mark.parametrize("value", ["0/2", "3/2", "1/1", "invalid"])
def test_invalid_shard_fails_closed(tmp_path: Path, value: str) -> None:
    (tmp_path / "test_sample.py").write_text("def test_one(): pass\n", encoding="utf-8")
    result = collect(tmp_path, f"--ci-shard={value}")
    assert result.returncode != 0
    assert "--ci-shard must be" in result.stderr
