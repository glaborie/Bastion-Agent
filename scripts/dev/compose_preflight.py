#!/usr/bin/env python3
"""Drop containers left bound to a network the daemon no longer has.

Docker stores a container's network binding by id. When the network is deleted
and recreated underneath it — a Docker Desktop restart, `docker network prune`,
a chaos run — every container created against the old id fails to start with

    Error response from daemon: failed to set up container networking:
    Could not attach to network <id>: rpc error: code = NotFound desc:
    network <id> not found

and `docker compose up` aborts after starting the healthy half of the stack. The
container's own config still names the right network; only the stored endpoint
id is stale, so compose reuses it instead of recreating it. Removing those
containers lets compose recreate them on the network that exists now. Volumes,
images and every healthy container are untouched.

    uv run python scripts/dev/compose_preflight.py [--project NAME] [--dry-run]

Exit codes: ``0`` nothing stale or cleaned, ``2`` docker is absent or the
project name cannot be resolved.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSPECT_FORMAT = "{{json .NetworkSettings.Networks}}"


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("docker")
    if binary is None:
        raise SystemExit("compose_preflight: docker is not on PATH")
    return subprocess.run(  # noqa: S603 - fixed docker CLI, arguments built here
        [binary, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def project_name() -> str:
    """The compose project this checkout renders, or its directory name."""
    result = docker("compose", "config", "--format", "json")
    if result.returncode == 0:
        try:
            name = json.loads(result.stdout).get("name")
        except json.JSONDecodeError:
            name = None
        if name:
            return str(name)
    return ROOT.name.lower()


def existing_networks() -> set[str]:
    """Network ids the daemon has; `--no-trunc` because the short form is a prefix."""
    return set(docker("network", "ls", "--no-trunc", "--quiet").stdout.split())


def containers(project: str) -> list[str]:
    result = docker("ps", "-aq", "--filter", f"label=com.docker.compose.project={project}")
    return result.stdout.split()


def _is_live(network_id: str, networks: set[str]) -> bool:
    # Either side may be truncated: `network ls` used to shorten ids to 12 chars.
    return any(
        known == network_id or known.startswith(network_id) or network_id.startswith(known)
        for known in networks
    )


def stale_network_ids(container: str, networks: set[str]) -> list[str]:
    """Network ids bound to a container that the daemon no longer has.

    An empty id counts as stale: it is a container whose attach never finished.
    """
    result = docker("inspect", container, "--format", INSPECT_FORMAT)
    try:
        attached: dict[str, dict[str, str]] = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return []
    missing: list[str] = []
    for network in attached.values():
        network_id = network.get("NetworkID", "")
        if not network_id or not _is_live(network_id, networks):
            missing.append(network_id)
    return missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Drop containers bound to a missing network.")
    parser.add_argument(
        "--project", default=None, help="compose project (default: this checkout's)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="report the stale containers, remove nothing"
    )
    args = parser.parse_args(argv)

    project = args.project or project_name()
    networks = existing_networks()
    stale: list[tuple[str, list[str]]] = []
    for container in containers(project):
        if missing := stale_network_ids(container, networks):
            name = docker("inspect", container, "--format", "{{.Name}}").stdout.strip().lstrip("/")
            stale.append((name, missing))

    if not stale:
        print(f"compose_preflight: every {project} container is bound to a network that exists")
        return 0

    for name, missing in stale:
        if args.dry_run:
            print(f"compose_preflight: would remove {name} (network {', '.join(missing)} is gone)")
            continue
        docker("rm", "-f", name)
        print(
            f"compose_preflight: removed {name} "
            f"(network {', '.join(missing)} is gone); compose will recreate it"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
