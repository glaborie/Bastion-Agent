#!/usr/bin/env python3
"""Check that the dev stack's credentials come from Vault, not `.env`.

`make vault-export` materialises every Vault-sourced credential (infra passwords
and application secrets) into a gitignored `.env.vault`; `make up` renders the
stack with that file layered over `.env`, and the app services load it as a
second `env_file` so a container sees the same values the interpolation used
(IDEA-056, IDEA-076). A later `--env-file`/`env_file` entry wins.

    uv run python scripts/check_env_vault.py            # keys present, required vars resolve
    uv run python scripts/check_env_vault.py --render   # sentinel precedence through Compose
    uv run python scripts/check_env_vault.py --vault    # .env.vault still matches Vault
    uv run python scripts/check_env_vault.py --check-plaintext  # no secret literal in .env

`--render` writes sentinel values into a temporary copy of `.env.vault`, renders
`docker compose config` with `.env.example` as the base, and fails if a sentinel
does not reach the config, if the base value for that key still appears, if the
sentinels appear when `.env.vault` is dropped, or if a required variable stops
resolving from the base file. It also proves the app containers keep the
container-internal `DATABASE_URL`/`REDIS_URL` from the compose anchor rather
than the host-localhost pair. No value is ever printed: failures name keys and
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

import yaml  # type: ignore[import-untyped]

# `python scripts/check_env_vault.py` puts only `scripts/` on sys.path, so the
# repo root must be added for `scripts._env` to resolve as it does under pytest.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts._env import read_env  # pylint: disable=wrong-import-position

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_VAULT = ROOT / ".env.vault"
DEFAULT_BASE_ENV = ROOT / ".env.example"
DEFAULT_ENV = ROOT / ".env"

#: Every key ``make vault-export`` writes from Vault, and the entry it comes from.
#: ``tests/test_env_vault.py`` fails if this map and the Makefile disagree.
VAULT_SECRETS: dict[str, str] = {
    # Infra credentials (IDEA-056).
    "POSTGRES_PASSWORD": "bastion/db/postgres",
    "POSTGRES_APP_USER": "bastion/db/postgres",
    "POSTGRES_APP_PASSWORD": "bastion/db/postgres",
    "REDIS_PASSWORD": "bastion/db/redis",
    "KEYCLOAK_ADMIN_PASSWORD": "bastion/db/keycloak",
    "KEYCLOAK_CLIENT_SECRET": "bastion/db/keycloak",
    "MINIO_ROOT_PASSWORD": "bastion/db/minio",
    # Application secrets (IDEA-076).
    "VAULT_MASTER_KEY": "bastion/app/dlp",
    "PAYLOAD_ESCROW_MASTER_KEY": "bastion/app/dlp",
    "APPROVAL_HMAC_SECRET": "bastion/app/jwt",
    "JOB_SIGNING_SECRET": "bastion/app/jwt",
    "AUDIT_WITNESS_ACCESS_KEY": "bastion/db/minio",
    "AUDIT_WITNESS_SECRET_KEY": "bastion/db/minio",
    "AUDIT_WITNESS_HMAC_SECRET": "bastion/app/audit",
    "OMNIROUTE_API_KEY": "bastion/app/oauth",
    "OMNIROUTE_ADMIN_PASSWORD": "bastion/db/omniroute",
    "PGADMIN_DEFAULT_PASSWORD": "bastion/db/pgadmin",
    "HF_TOKEN": "bastion/app/models",
    "OPENROUTER_API_KEY": "bastion/app/oauth",
    "LLAMA_API_KEY": "bastion/app/oauth",
    "LANGFUSE_SECRET_KEY": "bastion/app/observability",
    "ARIZE_API_KEY": "bastion/app/observability",
    "OPIK_API_KEY": "bastion/app/observability",
}

#: Externally-issued keys: `make vault-import` copies them from `.env` once and
#: writes an empty value when unset, so an empty export is not a failure.
OPTIONAL_SECRETS = frozenset(
    {
        "HF_TOKEN",
        "OPENROUTER_API_KEY",
        "LLAMA_API_KEY",
        "LANGFUSE_SECRET_KEY",
        "ARIZE_API_KEY",
        "OPIK_API_KEY",
    }
)

#: Host-side connection URLs, composed by `vault-export` from a Vault password
#: and the non-secret components in `.env`.
HOST_URL_KEYS = ("DATABASE_URL", "REDIS_URL")

#: The keys (IDEA-076 list) and URL passwords a developer `.env` must not carry.
PLAINTEXT_SECRETS = (
    "VAULT_MASTER_KEY",
    "APPROVAL_HMAC_SECRET",
    "JOB_SIGNING_SECRET",
    "PAYLOAD_ESCROW_MASTER_KEY",
    "AUDIT_WITNESS_ACCESS_KEY",
    "AUDIT_WITNESS_SECRET_KEY",
    "AUDIT_WITNESS_HMAC_SECRET",
    "OMNIROUTE_API_KEY",
    "OMNIROUTE_ADMIN_PASSWORD",
    "PGADMIN_DEFAULT_PASSWORD",
    "HF_TOKEN",
    "OPENROUTER_API_KEY",
    "LLAMA_API_KEY",
    "LANGFUSE_SECRET_KEY",
    "ARIZE_API_KEY",
    "OPIK_API_KEY",
)

#: Non-secret keys that must keep resolving from `.env` after the overlay.
BASE_ONLY_KEYS = (
    "POSTGRES_USER",
    "POSTGRES_DB",
    "POSTGRES_PORT",
    "PGADMIN_DEFAULT_EMAIL",
)

COMPOSE_FILES = ("-f", "docker-compose.yml", "-f", "docker-compose.vault.yml")
SENTINEL = "check-env-vault-sentinel"
BASE_SENTINEL = "check-env-vault-base"
VAR_REQUIRED = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*):\?")
URL_PASSWORD = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/@]*:([^@]*)@")


def required_vars() -> set[str]:
    """Every ``${NAME:?}`` the stack requires, across the compose files."""
    names: set[str] = set()
    for path in ("docker-compose.yml", "docker-compose.vault.yml"):
        names.update(VAR_REQUIRED.findall((ROOT / path).read_text(encoding="utf-8")))
    return names


def host_urls(host: dict[str, str], postgres_password: str, redis_password: str) -> dict[str, str]:
    """Compose the host-side URLs exactly as ``make vault-export`` does."""
    if not postgres_password or not redis_password:
        return {}
    return {
        "DATABASE_URL": (
            f"postgresql+asyncpg://{host.get('POSTGRES_USER', 'bastion')}:{postgres_password}"
            f"@localhost:{host.get('POSTGRES_PORT', '5432')}/{host.get('POSTGRES_DB', 'bastion')}"
        ),
        "REDIS_URL": f"redis://:{redis_password}@localhost:{host.get('REDIS_PORT', '6379')}/0",
    }


def check_offline(env_vault: Path, base_env: Path) -> list[str]:
    """No Vault, no Docker: the file carries every key and the stack can render."""
    problems: list[str] = []
    vault = read_env(env_vault)
    if not env_vault.is_file():
        return [f"{env_vault}: missing (run `make vault-export`) (key-free check)"]
    for key in VAULT_SECRETS:
        if not vault.get(key) and key not in OPTIONAL_SECRETS:
            problems.append(f"{key}: missing or empty in {env_vault.name}")
    for key in HOST_URL_KEYS:
        if not vault.get(key):
            problems.append(f"{key}: missing or empty in {env_vault.name}")
    resolved = read_env(base_env) | vault
    for name in sorted(required_vars()):
        if not resolved.get(name):
            problems.append(f"{name}: required by the compose files and set in neither file")
    return problems


def check_plaintext(env_path: Path) -> list[str]:
    """A secret typed into `.env` is a red check, not a review comment.

    `.env.example` is the template and keeps its development defaults, so it is
    exempt; a checkout with no `.env` (CI) passes.
    """
    if not env_path.is_file() or env_path.resolve() == DEFAULT_BASE_ENV.resolve():
        return []
    values = read_env(env_path)
    problems = [
        f"{key}: secret literal in {env_path.name}; keep it in .env.vault"
        for key in PLAINTEXT_SECRETS
        if values.get(key)
    ]
    for key in HOST_URL_KEYS:
        match = URL_PASSWORD.match(values.get(key, ""))
        if match and match.group(1):
            problems.append(f"{key}: password embedded in the host URL in {env_path.name}")
    return problems


def render(project: Path, env_files: list[str]) -> str:
    """``docker compose config`` for one project directory, no service started."""
    command = ["docker", "compose", "--profile", "compliance"]
    for name in env_files:
        command += ["--env-file", name]
    command += [*COMPOSE_FILES, "config"]
    # Compose gives the process environment precedence over --env-file, so the
    # keys under test are cleared: the check is about the files, not the shell.
    tested = {*VAULT_SECRETS, *HOST_URL_KEYS, *BASE_ONLY_KEYS}
    environment = {key: value for key, value in os.environ.items() if key not in tested}
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
    """Sentinels prove precedence, completeness and the container topology.

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
            "".join(f"{key}={SENTINEL}-{key}\n" for key in VAULT_SECRETS)
            + "".join(f"{key}={SENTINEL}-{key}\n" for key in HOST_URL_KEYS),
            encoding="utf-8",
        )
        layered_text = render(project, [".env", ".env.vault"])
        layered = yaml.safe_load(layered_text)
        # Dropping the file must remove every sentinel from the render, or the
        # overlay is not what put them there.
        (project / ".env.vault").unlink()
        dropped = render(project, [".env"])

    problems: list[str] = []
    for key in VAULT_SECRETS:
        if f"{SENTINEL}-{key}" not in layered_text:
            problems.append(f"{key}: the .env.vault value does not reach the rendered config")
        if f"{BASE_SENTINEL}-{key}" in layered_text:
            problems.append(f"{key}: the base value survives the overlay")
        if f"{SENTINEL}-{key}" in dropped:
            problems.append(f"{key}: rendered without .env.vault, so precedence is unproven")
        if not vault.get(key) and key not in OPTIONAL_SECRETS:
            problems.append(f"{key}: missing from {env_vault.name}")

    services = layered.get("services", {}) if isinstance(layered, dict) else {}
    for name in ("gateway", "worker"):
        environment = services.get(name, {}).get("environment", {})
        database_url = str(environment.get("DATABASE_URL", ""))
        redis_url = str(environment.get("REDIS_URL", ""))
        if "@db:5432/" not in database_url:
            problems.append(
                f"{name}: DATABASE_URL is not the container-internal compose anchor value"
            )
        if "@redis:6379/" not in redis_url:
            problems.append(f"{name}: REDIS_URL is not the container-internal compose anchor value")
    for key in BASE_ONLY_KEYS:
        value = base.get(key)
        if not value:
            problems.append(f"{key}: missing from {base_env.name}")
        elif value not in layered_text:
            problems.append(f"{key}: does not resolve from {base_env.name}")
    return problems


def compose_exec_args(env_vault: Path) -> list[str]:
    """`docker compose` invocation that can interpolate a stack whose `.env` is
    migrated: the required `${VAR:?}`s now live only in `.env.vault`."""
    args = ["docker", "compose"]
    if (ROOT / ".env").is_file():
        args += ["--env-file", ".env"]
    if env_vault.is_file():
        args += ["--env-file", str(env_vault)]
    return [*args, *COMPOSE_FILES, "exec"]


def _vault_field(key: str, path: str, env_vault: Path) -> str | None:
    """One field from the live Vault; ``None`` when the read failed."""
    command = [
        *compose_exec_args(env_vault),
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
        return None
    return result.stdout.rstrip("\n")


def check_vault(env_vault: Path, host_env: Path) -> list[str]:
    """Live Vault: every materialised value still matches its ``bastion/`` entry."""
    vault = read_env(env_vault)
    problems: list[str] = []
    live: dict[str, str] = {}
    for key, path in VAULT_SECRETS.items():
        value = _vault_field(key, path, env_vault)
        if value is None:
            problems.append(f"{key}: cannot read {path} from Vault (is it up and unsealed?)")
            continue
        live[key] = value
        if value != vault.get(key, ""):
            problems.append(f"{key}: differs from {path} in Vault; run `make vault-export`")
    expected = host_urls(
        read_env(host_env), live.get("POSTGRES_PASSWORD", ""), live.get("REDIS_PASSWORD", "")
    )
    for key in HOST_URL_KEYS:
        if key in expected and vault.get(key) != expected[key]:
            problems.append(
                f"{key}: does not match the Vault password and {host_env.name}; "
                "run `make vault-export`"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--render", action="store_true", help="prove precedence with sentinels")
    parser.add_argument("--vault", action="store_true", help="compare against a running Vault")
    parser.add_argument(
        "--check-plaintext", action="store_true", help="fail on a secret literal in .env"
    )
    parser.add_argument("--env-vault", type=Path, default=DEFAULT_ENV_VAULT)
    parser.add_argument("--base-env", type=Path, default=DEFAULT_BASE_ENV)
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV, help="the developer .env")
    args = parser.parse_args(argv)

    if shutil.which("docker") is None:
        print("check-env-vault: docker is not on PATH", file=sys.stderr)
        return 2

    if args.check_plaintext:
        problems = check_plaintext(args.env)
    elif args.vault:
        problems = check_offline(args.env_vault, args.base_env) + check_vault(
            args.env_vault, args.env
        )
    elif args.render:
        problems = check_render(args.env_vault, args.base_env)
    else:
        problems = check_offline(args.env_vault, args.base_env)

    if problems:
        for problem in problems:
            print(f"check-env-vault: {problem}", file=sys.stderr)
        return 1
    if args.check_plaintext:
        print(f"check-env-vault: no secret literal in {args.env.name}")
    elif args.render:
        print(f"check-env-vault: {len(VAULT_SECRETS)} key(s) win through Compose")
    else:
        print(
            f"check-env-vault: {len(VAULT_SECRETS)} key(s) from Vault, "
            f"the rest from {args.base_env.name}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
