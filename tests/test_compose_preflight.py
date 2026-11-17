"""The compose preflight that drops containers bound to a deleted network."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "dev" / "compose_preflight.py"

# The state a Docker Desktop restart or a `docker network prune` leaves behind:
# `stale-a` holds an endpoint id whose network is gone, `never-attached` was
# created against a network that vanished mid-attach, and `healthy` points at
# the network the daemon still has. The network list is short-form, as
# `docker network ls` prints it, while the container holds the full id.
FAKE_DOCKER = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["FAKE_DOCKER_LOG"]).open("a", encoding="utf-8") as fh:
    fh.write(" ".join(args) + "\\n")

containers = {
    "ca": ("/stale-a", "3cdb3d40d233"),
    "cb": ("/healthy", "7938bbb56f04ada425a21df2137a8f66512aff307fd222105827b17472413bc8"),
    "cc": ("/never-attached", ""),
}

if args[:3] == ["compose", "config", "--format"]:
    print(json.dumps({"name": "demo"}))
elif args[:2] == ["network", "ls"]:
    print("7938bbb56f04")
elif args[:2] == ["ps", "-aq"]:
    print("\\n".join(containers) if args[-1].endswith("=demo") else "")
elif args[0] == "inspect" and args[2] == "--format":
    name, network_id = containers[args[1]]
    if args[3] == "{{.Name}}":
        print(name)
    else:
        print(json.dumps({"bastion-agent_bastion-net": {"NetworkID": network_id}}))
"""


def fake_docker(tmp_path: Path) -> tuple[Path, Path]:
    binary = tmp_path / "bin" / "docker"
    binary.parent.mkdir()
    binary.write_text(FAKE_DOCKER, encoding="utf-8")
    binary.chmod(0o755)
    return binary.parent, tmp_path / "calls.log"


def run(tmp_path: Path, *args: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    binary_dir, log = fake_docker(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{binary_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_DOCKER_LOG": str(log),
    }
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    return result, log.read_text(encoding="utf-8").splitlines()


def test_only_containers_on_a_deleted_network_are_removed(tmp_path: Path) -> None:
    result, calls = run(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "rm -f stale-a" in calls
    assert "rm -f never-attached" in calls
    assert "rm -f healthy" not in calls
    assert "removed stale-a" in result.stdout


def test_dry_run_names_them_and_removes_nothing(tmp_path: Path) -> None:
    result, calls = run(tmp_path, "--dry-run")

    assert result.returncode == 0
    assert "would remove stale-a" in result.stdout
    assert not [call for call in calls if call.startswith("rm ")]


def test_a_stack_on_live_networks_is_left_alone(tmp_path: Path) -> None:
    result, calls = run(tmp_path, "--project", "other")

    assert result.returncode == 0
    assert result.stdout.startswith("compose_preflight: every other container")
    assert not [call for call in calls if call.startswith("rm ")]
