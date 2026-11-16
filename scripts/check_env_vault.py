#!/usr/bin/env python3
"""Check that the dev stack's infra credentials come from Vault, not `.env`.

`make vault-export` materialises infra credentials into a gitignored `.env.vault`;
`make up` renders the stack with that file layered over `.env`, and the app
services load it as a second `env_file` so a container sees the same values the
interpolation used (IDEA-056). A later `--env-file`/`env_file` entry wins, so the
seven keys below come from Vault and everything else still comes from `.env`.

    uv run python scripts/check_env_vault.py            # keys present, required vars resolve
    uv run python scripts/check_env_vault.py --render   # sentinel precedence through Compose
    uv run python scripts/check_env_vault.py --vault    # .env.vault still matches Vault

`--render` writes sentinel values into a temporary copy of `.env.vault`, renders
`docker compose config` with `.env.example` as the base, and fails if a sentinel
does not reach the config, if the base value for that key still appears, if the
sentinels appear when `.env.vault` is dropped, or if a required variable stops
resolving from the base file. No value is ever printed: failures name keys and
paths only.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_VAULT = ROOT / ".env.vault"
DEFAULT_BASE_ENV = ROOT / ".env.example"

#: The keys ``make vault-export`` writes, and the Vault entry each comes from.
#: ``tests/test_env_vault.py`` fails if this map and the Makefile disagree.
VAULT_SECRETS: dict[str, str] = {
    "POSTGRES_PASSWORD": "bastion/db/postgres",
    "POSTGRES_APP_USER": "bastion/db/postgres",
    "POSTGRES_APP_PASSWORD": "bastion/db/postgres",
    "REDIS_PASSWORD": "bastion/db/redis",
    "KEYCLOAK_ADMIN_PASSWORD": "bastion/db/keycloak",
    "KEYCLOAK_CLIENT_SECRET": "bastion/db/keycloak",
    "MINIO_ROOT_PASSWORD": "bastion/db/minio",
}

#: Keys that must keep resolving from `.env` (the base file) after the overlay.
BASE_ONLY_KEYS = (
    "VAULT_MASTER_KEY",
    "APPROVAL_HMAC_SECRET",
    "OMNIROUTE_ADMIN_PASSWORD",
    "PGADMIN_DEFAULT_EMAIL",
    "PGADMIN_DEFAULT_PASSWORD",
)

COMPOSE_FILES = ("-f", "docker-compose.yml", "-f", "docker-compose.vault.yml")
SENTINEL = "check-env-vault-sentinel"
BASE_SENTINEL = "check-env-vault-base"
VAR_REQUIRED = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*):\?")


def read_env(path: Path) -> dict[str, str]:
    """Read a Compose-style ``.env``: KEY=VALUE, optional quotes, # comments."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].lstrip()
        key, separator, value = stripped.partition("=")
        if not separator:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def required_vars() -> set[str]:
    """Every ``${NAME:?}`` the stack requires, across the compose files."""
    names: set[str] = set()
    for path in ("docker-compose.yml", "docker-compose.vault.yml"):
        names.update(VAR_REQUIRED.findall((ROOT / path).read_text(encoding="utf-8")))
    return names


def check_offline(env_vault: Path, base_env: Path) -> list[str]:
    """No Vault, no Docker: the file carries every key and the stack can render."""
    problems: list[str] = []
    vault = read_env(env_vault)
    if not env_vault.is_file():
        return [f"{env_vault}: missing (run `make vault-export`) (key-free check)"]
    for key in VAULT_SECRETS:
        if not vault.get(key):
            problems.append(f"{key}: missing or empty in {env_vault.name}")
    resolved = read_env(base_env) | vault
    for name in sorted(required_vars()):
        if not resolved.get(name):
            problems.append(f"{name}: required by the compose files and set in neither file")
    return problems


def render(project: Path, env_files: list[str]) -> str:
    """``docker compose config`` for one project directory, no service started."""
    command = ["docker", "compose", "--profile", "compliance"]
    for name in env_files:
        command += ["--env-file", name]
    command += [*COMPOSE_FILES, "config"]
    # Compose gives the process environment precedence over --env-file, so the
    # keys under test are cleared: the check is about the files, not the shell.
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {*VAULT_SECRETS, *BASE_ONLY_KEYS}
    }
    result = subprocess.run(  # noqa: S603 - fixed docker CLI, names built here
        command,
        cwd=project,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
        env=environment,
    )
    if result.returncode != 0:
        detail = result.stderr.strip()
        raise SystemExit(f"check-env-vault: `docker compose config` failed: {detail}")
    return result.stdout


def _with_base_sentinels(base_env: Path) -> str:
    """The base file with a distinct sentinel for every Vault-materialised key."""
    lines: list[str] = []
    for line in (base_env.read_text(encoding="utf-8") if base_env.is_file() else "").splitlines():
        key = line.partition("=")[0].strip()
        lines.append(f"{key}={BASE_SENTINEL}-{key}" if key in VAULT_SECRETS else line)
    return "\n".join(lines) + "\n"


def check_render(env_vault: Path, base_env: Path) -> list[str]:
    """Sentinels prove precedence and completeness through Compose itself.

    Both inputs are copies and each Vault-materialised key gets a distinctive
    sentinel, so a surviving base value is unmistakable and no real credential
    enters the comparison. Rendering a temporary project proves both layers: the
    ``--env-file`` interpolation and the ``env_file`` a container receives.
    """
    vault = read_env(env_vault)
    base = read_env(base_env)
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory)
        for name in ("docker-compose.yml", "docker-compose.vault.yml"):
            shutil.copy(ROOT / name, project / name)
        (project / ".env").write_text(_with_base_sentinels(base_env), encoding="utf-8")
        (project / ".env.vault").write_text(
            "".join(f"{key}={SENTINEL}-{key}\n" for key in VAULT_SECRETS), encoding="utf-8"
        )
        layered = render(project, [".env", ".env.vault"])
        # Dropping the file must remove every sentinel from the render, or the
        # overlay is not what put them there.
        (project / ".env.vault").unlink()
        dropped = render(project, [".env"])

    problems: list[str] = []
    for key in VAULT_SECRETS:
        if f"{SENTINEL}-{key}" not in layered:
            problems.append(f"{key}: the .env.vault value does not reach the rendered config")
        if f"{BASE_SENTINEL}-{key}" in layered:
            problems.append(f"{key}: the base value survives the overlay")
        if f"{SENTINEL}-{key}" in dropped:
            problems.append(f"{key}: rendered without .env.vault, so precedence is unproven")
        if not vault.get(key):
            problems.append(f"{key}: missing from {env_vault.name}")
    for key in BASE_ONLY_KEYS:
        value = base.get(key)
        if not value:
            problems.append(f"{key}: missing from {base_env.name}")
        elif value not in layered:
            problems.append(f"{key}: does not resolve from {base_env.name}")
    return problems


def check_vault(env_vault: Path) -> list[str]:
    """Live Vault: every materialised value still matches its ``bastion/`` entry."""
    vault = read_env(env_vault)
    problems: list[str] = []
    for key, path in VAULT_SECRETS.items():
        value = vault.get(key)
        if not value:
            problems.append(f"{key}: missing from {env_vault.name}")
            continue
        command = [
            "docker",
            "compose",
            *COMPOSE_FILES,
            "exec",
            "-T",
            "-e",
            "VAULT_SKIP_VERIFY=true",
            "vault",
            "vault",
            "kv",
            "get",
            "-field",
            key,
            path,
        ]
        result = subprocess.run(  # noqa: S603 - fixed docker CLI, key and path are literals
            command, cwd=ROOT, capture_output=True, text=True, check=False, timeout=60
        )
        if result.returncode != 0:
            problems.append(f"{key}: cannot read {path} from Vault (is it up and unsealed?)")
        elif result.stdout.strip() != value:
            problems.append(f"{key}: differs from {path} in Vault; run `make vault-export`")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--render", action="store_true", help="prove precedence with sentinels")
    parser.add_argument("--vault", action="store_true", help="compare against a running Vault")
    parser.add_argument("--env-vault", type=Path, default=DEFAULT_ENV_VAULT)
    parser.add_argument("--base-env", type=Path, default=DEFAULT_BASE_ENV)
    args = parser.parse_args(argv)

    if shutil.which("docker") is None:
        print("check-env-vault: docker is not on PATH", file=sys.stderr)
        return 2

    problems: list[str] = []
    if args.vault:
        problems = check_offline(args.env_vault, args.base_env) + check_vault(args.env_vault)
    elif args.render:
        problems = check_render(args.env_vault, args.base_env)
    else:
        problems = check_offline(args.env_vault, args.base_env)

    if problems:
        for problem in problems:
            print(f"check-env-vault: {problem}", file=sys.stderr)
        return 1
    print(
        f"check-env-vault: {len(VAULT_SECRETS)} key(s) from Vault, "
        f"the rest from {args.base_env.name}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
