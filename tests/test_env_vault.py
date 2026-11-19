"""The dev stack's credentials come from Vault, not the hand-typed `.env`.

``make vault-export`` writes `.env.vault`; ``make up`` layers it over `.env` and
the app services load it as a second ``env_file``, so a later entry wins. These
tests pin the precedence, the fail-closed checks, the no-value-in-output rule
and the plaintext guard (IDEA-056, IDEA-076) without needing a live Vault.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.check_env_vault import (
    OPTIONAL_SECRETS,
    PLAINTEXT_SECRETS,
    VAULT_SECRETS,
)

ROOT = Path(__file__).resolve().parents[1]
MAKE = shutil.which("make")
EXAMPLE = ROOT / ".env.example"
CHECK = ROOT / "scripts" / "check_env_vault.py"
KEYS = tuple(VAULT_SECRETS)
SENTINEL_VALUE = "env-vault-test-secret-value"

needs_docker = pytest.mark.skipif(shutil.which("docker") is None, reason="needs docker compose")


def python(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECK), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env={**os.environ, **(env or {})},
    )


def example_value(key: str) -> str:
    for line in EXAMPLE.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if separator and name.strip() == key:
            return value.strip()
    raise AssertionError(f"{key} is missing from .env.example")


def write_env_vault(path: Path, *, omit: str | None = None) -> Path:
    lines = [f"{key}={SENTINEL_VALUE}-{key}\n" for key in KEYS if key != omit]
    lines.append(
        f"DATABASE_URL=postgresql+asyncpg://bastion:{SENTINEL_VALUE}"
        "-POSTGRES_PASSWORD@localhost:5432/bastion\n"
    )
    lines.append(f"REDIS_URL=redis://:{SENTINEL_VALUE}-REDIS_PASSWORD@localhost:6379/0\n")
    path.write_text("".join(lines), encoding="utf-8")
    return path


def write_host_env(path: Path) -> Path:
    path.write_text(
        "POSTGRES_USER=bastion\nPOSTGRES_DB=bastion\nPOSTGRES_PORT=5432\n"
        "REDIS_PORT=6379\nPOSTGRES_PASSWORD=dev-only-postgres-password\n",
        encoding="utf-8",
    )
    return path


@needs_docker
def test_render_proves_env_vault_precedence(tmp_path: Path) -> None:
    """Interpolation and the container env_file both carry the overlaid value."""
    vault = write_env_vault(tmp_path / ".env.vault")

    result = python("--render", "--env-vault", str(vault))

    assert result.returncode == 0, result.stderr


def test_a_missing_key_fails_offline_naming_only_the_key(tmp_path: Path) -> None:
    vault = write_env_vault(tmp_path / ".env.vault", omit="MINIO_ROOT_PASSWORD")

    result = python("--env-vault", str(vault))

    assert result.returncode == 1
    assert "MINIO_ROOT_PASSWORD" in result.stderr
    assert SENTINEL_VALUE not in result.stdout + result.stderr


def test_an_externally_issued_key_may_be_empty(tmp_path: Path) -> None:
    """`vault-import` writes an empty value when a key is unset."""
    vault = write_env_vault(tmp_path / ".env.vault")
    vault.write_text(
        vault.read_text(encoding="utf-8").replace(
            f"HF_TOKEN={SENTINEL_VALUE}-HF_TOKEN\n", "HF_TOKEN=\n"
        ),
        encoding="utf-8",
    )

    result = python("--env-vault", str(vault))

    assert result.returncode == 0, result.stderr


def test_a_required_variable_set_in_neither_file_fails(tmp_path: Path) -> None:
    vault = write_env_vault(tmp_path / ".env.vault", omit="VAULT_MASTER_KEY")
    base = tmp_path / ".env.example"
    base.write_text(
        "\n".join(
            line
            for line in EXAMPLE.read_text(encoding="utf-8").splitlines()
            if not line.startswith("VAULT_MASTER_KEY=")
        ),
        encoding="utf-8",
    )

    result = python("--env-vault", str(vault), "--base-env", str(base))

    assert result.returncode == 1
    assert "VAULT_MASTER_KEY" in result.stderr


def test_drift_from_vault_fails_without_printing_the_value(tmp_path: Path) -> None:
    vault = write_env_vault(tmp_path / ".env.vault")
    host = write_host_env(tmp_path / ".env")
    binary = tmp_path / "bin"
    binary.mkdir()
    docker = binary / "docker"
    docker.write_text(
        "#!/bin/bash\n"
        'key=""\n'
        'previous=""\n'
        'for arg in "$@"; do\n'
        '    [ "$previous" = "-field" ] && key="$arg"\n'
        '    previous="$arg"\n'
        "done\n"
        'if [ "$key" = MINIO_ROOT_PASSWORD ]; then echo "rotated-elsewhere"; '
        'else echo "$SENTINEL_VALUE-$key"; fi\n',
        encoding="utf-8",
    )
    docker.chmod(0o755)

    result = python(
        "--vault",
        "--env-vault",
        str(vault),
        "--env",
        str(host),
        env={"PATH": f"{binary}{os.pathsep}{os.environ['PATH']}"},
    )

    assert result.returncode == 1
    assert "MINIO_ROOT_PASSWORD" in result.stderr
    assert "bastion/db/minio" in result.stderr
    assert SENTINEL_VALUE not in result.stdout + result.stderr


def test_make_up_layers_env_vault_only_when_it_exists(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("POSTGRES_PASSWORD=from-dot-env\n", encoding="utf-8")

    def make_up() -> str:
        return subprocess.run(
            [MAKE or "make", "-n", "-f", str(ROOT / "Makefile"), "up"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout

    without = make_up()
    assert "--env-file .env " in without + " "
    assert ".env.vault" not in without

    (tmp_path / ".env.vault").write_text("POSTGRES_PASSWORD=from-vault\n", encoding="utf-8")
    with_vault = make_up()
    assert "--env-file .env --env-file .env.vault" in with_vault


def test_the_check_covers_exactly_the_keys_make_vault_export_writes() -> None:
    """One map: the export target and the checker cannot drift apart."""
    exported = re.findall(
        r'-field=(\w+) (bastion/[^\s")]+)',
        (ROOT / "Makefile").read_text(encoding="utf-8"),
    )
    assert exported, "no vault-export entries found in the Makefile"

    imported = json.loads(
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import json, sys; sys.path.insert(0, '.'); "
                "from scripts.check_env_vault import VAULT_SECRETS; "
                "print(json.dumps(VAULT_SECRETS))",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout
    )

    assert imported == dict(exported)


def test_a_secret_literal_in_env_fails_naming_only_the_key(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "VAULT_MASTER_KEY=do-not-print-this-key\nAPP_NAME=bastion-agent\n", encoding="utf-8"
    )

    result = python("--check-plaintext", "--env", str(env))

    assert result.returncode == 1
    assert "VAULT_MASTER_KEY" in result.stderr
    assert "do-not-print-this-key" not in result.stdout + result.stderr


def test_a_password_in_the_host_urls_fails_naming_the_key(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "DATABASE_URL=postgresql+asyncpg://bastion:embedded-password@localhost:5432/bastion\n"
        "REDIS_URL=redis://:redis-embedded-password@localhost:6379/0\n",
        encoding="utf-8",
    )

    result = python("--check-plaintext", "--env", str(env))

    assert result.returncode == 1
    assert "DATABASE_URL" in result.stderr
    assert "REDIS_URL" in result.stderr
    assert "embedded-password" not in result.stdout + result.stderr


def test_the_template_and_an_absent_env_pass_the_plaintext_check(tmp_path: Path) -> None:
    assert python("--check-plaintext", "--env", str(EXAMPLE)).returncode == 0
    assert python("--check-plaintext", "--env", str(tmp_path / ".env")).returncode == 0


def test_the_plaintext_list_is_the_sixteen_named_keys() -> None:
    assert len(PLAINTEXT_SECRETS) == 16
    assert set(PLAINTEXT_SECRETS) <= set(VAULT_SECRETS)
    assert len(OPTIONAL_SECRETS) == 6
    # The template keeps a development default so a clone without Vault starts.
    assert example_value("VAULT_MASTER_KEY")
