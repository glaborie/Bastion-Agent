#!/usr/bin/env python3
"""Snapshot and restore the dev stack's durable state before a destructive reset.

    uv run python scripts/dev/backup_dev.py backup
    uv run python scripts/dev/backup_dev.py restore .artifacts/backups/20261120T120000Z
    uv run python scripts/dev/backup_dev.py restore <dir> --force

`make backup` and `make restore BACKUP=<dir>` wrap the two subcommands. A
snapshot holds `pg_dump` output, the audit-witness bucket and one Keycloak realm
under `.artifacts/backups/<UTC timestamp>/`, with a `manifest.json` that records
every file's SHA-256 and size. Restore refuses a missing manifest, a digest
mismatch, or a target that already has audit rows or witness objects unless
`--force` is given.

This is a development convenience, not a backup control: a point-in-time copy,
no WAL, no off-host copy and no encryption beyond the volumes it writes to. The
witness bucket is object-locked, so restore always targets a freshly initialised
bucket (`minio-init` created it at `up`) and re-applies each object's recorded
retention date.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts._env import read_env  # pylint: disable=wrong-import-position

ROOT = Path(__file__).resolve().parents[2]
BACKUP_ROOT = ROOT / ".artifacts" / "backups"
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.vault.yml")
REQUIRED_SERVICES = ("db", "minio", "keycloak")
HEALTH_TIMEOUT_SECONDS = 180
KEYCLOAK_DATA = "/opt/keycloak/data"


def _fail(message: str) -> None:
    raise SystemExit(f"dev-backup: {message}")


def _run(
    command: Sequence[str], *, stdin: bytes | None = None, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(  # noqa: S603 - argv is built here from fixed docker/psql calls
        command, cwd=ROOT, input=stdin, capture_output=True, check=False
    )
    if check and result.returncode != 0:
        detail = " | ".join(
            line
            for line in (result.stderr or result.stdout).decode("utf-8", "replace").splitlines()
            if line.strip()
        )
        _fail(f"`{' '.join(command[:3])} …` failed: {detail[-300:]}")
    return result


def _compose_files() -> list[str]:
    override = os.environ.get("COMPOSE_FILE")
    return override.split(os.pathsep) if override else list(COMPOSE_FILES)


def _compose(*args: str, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    command = ["docker", "compose", "--project-directory", str(ROOT)]
    for name in (".env", ".env.vault"):
        if (ROOT / name).is_file():
            command += ["--env-file", name]
    for name in _compose_files():
        command += ["-f", name]
    return _run([*command, *args], **kwargs)


def _env_values() -> dict[str, str]:
    return read_env(ROOT / ".env") | read_env(ROOT / ".env.vault")


def _compose_config() -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(_compose("config", "--format", "json").stdout)
    return payload


def _states() -> dict[str, tuple[str, str]]:
    states: dict[str, tuple[str, str]] = {}
    for line in _compose("ps", "--format", "json", "--all", check=False).stdout.split(b"\n"):
        if not line.strip():
            continue
        item = json.loads(line)
        states[str(item.get("Service", ""))] = (
            str(item.get("State", "")),
            str(item.get("Health", "")),
        )
    return states


def _database_args(values: dict[str, str]) -> list[str]:
    return [
        "-U",
        values.get("POSTGRES_USER", "bastion"),
        "-d",
        values.get("POSTGRES_DB", "bastion"),
    ]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _keycloak_volume() -> str:
    container = _compose("ps", "-a", "-q", "keycloak").stdout.decode().strip()
    if not container:
        _fail("keycloak has no container; start the stack with `make up`")
    volume = (
        _run(
            [
                "docker",
                "inspect",
                "-f",
                '{{range .Mounts}}{{if eq .Destination "'
                + KEYCLOAK_DATA
                + '"}}{{.Name}}{{end}}{{end}}',
                container,
            ]
        )
        .stdout.decode()
        .strip()
    )
    if not volume:
        _fail("could not find the Keycloak data volume")
    return volume


def _keycloak_image() -> str:
    return str(_compose_config()["services"]["keycloak"]["image"])


def _keycloak_oneshot(arguments: Sequence[str], *, mount: Path) -> None:
    _run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-v",
            f"{_keycloak_volume()}:{KEYCLOAK_DATA}",
            "-v",
            f"{mount}:/backup",
            _keycloak_image(),
            *arguments,
        ]
    )


def _dump_database(target: Path, values: dict[str, str]) -> None:
    result = _compose(
        "exec", "-T", "db", "pg_dump", *_database_args(values), "--no-owner", "--no-privileges"
    )
    target.write_bytes(result.stdout)


def _witness_client() -> Any:
    from db.witness import witness_client  # imported here: the ledger needs no store
    from settings import get_settings

    return witness_client(get_settings())


def _mirror_witness(directory: Path) -> dict[str, Any]:
    client = _witness_client()
    bucket = _witness_bucket()
    objects: list[dict[str, Any]] = []
    paginator = client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for item in page.get("Contents", []):
            key = str(item["Key"])
            head = client.head_object(Bucket=bucket, Key=key)
            body = client.get_object(Bucket=bucket, Key=key)["Body"].read()
            target = directory / key
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            retain = head.get("ObjectLockRetainUntilDate")
            objects.append(
                {
                    "key": key,
                    "file": str(target.relative_to(directory.parent)),
                    "retain_until": retain.isoformat() if retain else None,
                    "version_id": head.get("VersionId"),
                }
            )
    return {"bucket": bucket, "objects": objects}


def _witness_bucket() -> str:
    from settings import get_settings

    return get_settings().audit_witness_bucket


def _export_realm(directory: Path, values: dict[str, str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    realm = values.get("KEYCLOAK_REALM", "bastion")
    _compose("stop", "keycloak")
    try:
        _keycloak_oneshot(
            ["export", "--dir", "/backup", "--realm", realm, "--users", "realm_file"],
            mount=directory,
        )
    finally:
        _compose("start", "keycloak")
    if not any(directory.glob("*.json")):
        _fail(f"Keycloak exported no realm file for {realm}")


def _manifest(staging: Path, witness: dict[str, Any]) -> dict[str, Any]:
    files = [
        {
            "path": str(path.relative_to(staging)),
            "sha256": _sha256(path),
            "size": path.stat().st_size,
        }
        for path in sorted(staging.rglob("*"))
        if path.is_file()
    ]
    return {
        "created_at": datetime.now(UTC).isoformat(),
        "files": files,
        "witness": witness,
    }


def backup() -> int:
    states = _states()
    for name in REQUIRED_SERVICES:
        state, _ = states.get(name, ("", ""))
        if state != "running":
            _fail(f"{name} is not running; start the stack with `make up`")

    values = _env_values()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = BACKUP_ROOT / timestamp
    if destination.exists():
        _fail(f"{destination} already exists")
    staging = BACKUP_ROOT / f".{timestamp}.partial"
    shutil.rmtree(staging, ignore_errors=True)

    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    staging.mkdir(mode=0o700)
    try:
        _dump_database(staging / "postgres.sql", values)
        witness = _mirror_witness(staging / "witness")
        _export_realm(staging / "keycloak", values)
        payload = _manifest(staging, witness)
        (staging / "manifest.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        staging.rename(destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    print(
        f"backup: {destination} ({len(payload['files'])} file(s), "
        f"{len(witness['objects'])} witness object(s))"
    )
    return 0


def _load_manifest(directory: Path) -> dict[str, Any]:
    manifest = directory / "manifest.json"
    if not manifest.is_file():
        _fail(f"{directory} has no manifest.json")
    payload: dict[str, Any] = json.loads(manifest.read_text(encoding="utf-8"))
    root = directory.resolve()
    for entry in payload.get("files", []):
        target = (directory / str(entry["path"])).resolve()
        if root not in target.parents:
            _fail(f"manifest path escapes the snapshot: {entry['path']}")
        if not target.is_file():
            _fail(f"{entry['path']} is missing from the snapshot")
        data = target.read_bytes()
        if len(data) != int(entry["size"]) or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            _fail(f"{entry['path']} does not match its digest")
    return payload


def _wait_healthy() -> None:
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    pending = set(REQUIRED_SERVICES)
    while pending and time.monotonic() < deadline:
        states = _states()
        for name in sorted(pending):
            state, health = states.get(name, ("", ""))
            if state == "running" and health in {"", "healthy"}:
                pending.discard(name)
            elif state in {"exited", "dead"}:
                _fail(f"{name} exited while starting the stack")
        if pending:
            time.sleep(3)
    if pending:
        _fail(f"{', '.join(sorted(pending))} did not become healthy in {HEALTH_TIMEOUT_SECONDS}s")


def _wait_minio_init() -> None:
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        for line in _compose("ps", "--format", "json", "--all", check=False).stdout.split(b"\n"):
            if not line.strip():
                continue
            item = json.loads(line)
            if item.get("Service") == "minio-init" and item.get("State") == "exited":
                if int(item.get("ExitCode", 1)) != 0:
                    _fail("minio-init failed; the witness bucket was not initialised")
                return
        time.sleep(2)
    _fail("minio-init did not finish; the witness bucket is not ready")


def _start_stack() -> None:
    _compose("--profile", "compliance", "up", "-d", "db", "minio", "minio-init", "keycloak")
    _wait_healthy()
    _wait_minio_init()


def _witness_count() -> int:
    client = _witness_client()
    bucket = _witness_bucket()
    count = 0
    for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        count += len(page.get("Contents", []))
    return count


def _occupancy(values: dict[str, str]) -> list[str]:
    found: list[str] = []
    for query, label in (
        ("SELECT count(*) FROM audit_logs", "audit row(s)"),
        ("SELECT count(*) FROM pending_approvals", "approval row(s)"),
    ):
        result = _compose(
            "exec", "-T", "db", "psql", *_database_args(values), "-tAc", query, check=False
        )
        if result.returncode == 0:
            count = int(result.stdout.decode().strip() or 0)
            if count:
                found.append(f"{count} {label}")
    objects = _witness_count()
    if objects:
        found.append(f"{objects} witness object(s)")
    return found


def _restore_database(directory: Path, values: dict[str, str], *, force: bool) -> None:
    dump = directory / "postgres.sql"
    if not dump.is_file():
        _fail("the snapshot has no postgres.sql")
    if force:
        _compose(
            "exec",
            "-T",
            "db",
            "psql",
            *_database_args(values),
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        )
    _compose(
        "exec",
        "-T",
        "db",
        "psql",
        *_database_args(values),
        "-v",
        "ON_ERROR_STOP=1",
        "-f",
        "-",
        stdin=dump.read_bytes(),
    )


def _restore_witness(directory: Path, payload: dict[str, Any]) -> None:
    witness = payload.get("witness", {})
    client = _witness_client()
    bucket = _witness_bucket()
    fallback = datetime.now(UTC) + timedelta(days=365 * 7)
    for entry in witness.get("objects", []):
        body = (directory / str(entry["file"])).read_bytes()
        raw = entry.get("retain_until")
        retain = datetime.fromisoformat(raw) if raw else fallback
        client.put_object(
            Bucket=bucket,
            Key=str(entry["key"]),
            Body=body,
            ContentType="application/json",
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain,
        )


def _import_realm(directory: Path) -> None:
    source = directory / "keycloak"
    exported = sorted(source.glob("*.json"))
    if not exported:
        _fail("the snapshot has no Keycloak realm export")
    _compose("stop", "keycloak")
    try:
        _keycloak_oneshot(
            ["import", "--file", f"/backup/{exported[0].name}", "--override", "true"],
            mount=source,
        )
    finally:
        _compose("start", "keycloak")


def restore(directory: Path, *, force: bool) -> int:
    directory = directory.resolve()
    payload = _load_manifest(directory)
    values = _env_values()
    _start_stack()
    if not force:
        occupied = _occupancy(values)
        if occupied:
            _fail(f"{directory.name} target is not empty: {', '.join(occupied)} (pass FORCE=1)")
    _restore_database(directory, values, force=force)
    _restore_witness(directory, payload)
    _import_realm(directory)
    print(f"restore: loaded {directory} ({len(payload.get('files', []))} file(s))")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ or "Dev data snapshot and restore.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("backup", help="write a snapshot under .artifacts/backups/")
    restore_parser = subcommands.add_parser("restore", help="load a snapshot into the stack")
    restore_parser.add_argument("directory", type=Path, metavar="BACKUP")
    restore_parser.add_argument(
        "--force", action="store_true", help="allow a target that already holds audit data"
    )
    args = parser.parse_args(argv)
    if args.command == "backup":
        return backup()
    return restore(args.directory, force=bool(args.force))


if __name__ == "__main__":
    raise SystemExit(main())
