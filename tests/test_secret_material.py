"""The gate guard for certificate and key material (IDEA-058).

The check is exercised against throwaway git repositories so the real tree's
cleanliness is not what makes the assertions true.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_secret_material.py"
GITIGNORE = ROOT / ".gitignore"
PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n"
CERTIFICATE = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n"


def run_check(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def load_check() -> ModuleType:
    """Import the script as a module so its allowlist can be exercised directly."""
    spec = importlib.util.spec_from_file_location("check_secret_material", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],  # noqa: S607 - resolved from PATH by design
        check=True,
        capture_output=True,
    )


def make_repo(tmp_path: Path, gitignore: str | None = None) -> Path:
    """A git repository whose .gitignore is the real one, optionally edited."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "--quiet")
    git(root, "config", "user.email", "gate@example.invalid")
    git(root, "config", "user.name", "gate")
    text = GITIGNORE.read_text(encoding="utf-8") if gitignore is None else gitignore
    (root / ".gitignore").write_text(text, encoding="utf-8")
    git(root, "add", ".gitignore")
    git(root, "commit", "--quiet", "-m", "base")
    return root


def without_vault_certs_rule() -> str:
    """The real .gitignore with every `vault/certs/` rule stripped."""
    return "".join(
        line
        for line in GITIGNORE.read_text(encoding="utf-8").splitlines(keepends=True)
        if line.strip() != "vault/certs/"
    )


def without_env_rules() -> str:
    """The real .gitignore with the `.env` and `.env.*` rules stripped."""
    return "".join(
        line
        for line in GITIGNORE.read_text(encoding="utf-8").splitlines(keepends=True)
        if line.strip() not in {".env", ".env.*"}
    )


def test_the_repository_itself_is_clean() -> None:
    result = run_check(ROOT)

    assert result.returncode == 0, result.stdout + result.stderr
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"],  # noqa: S607 - resolved from PATH
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    assert [p for p in tracked if p.lower().endswith((".crt", ".key", ".pem"))] == []


def test_a_tracked_key_and_certificate_fail_without_printing_content(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    (root / "dummy.key").write_text(PRIVATE_KEY, encoding="utf-8")
    (root / "leaf.crt").write_text(CERTIFICATE, encoding="utf-8")
    git(root, "add", "dummy.key", "leaf.crt")
    git(root, "commit", "--quiet", "-m", "mistake")

    result = run_check(root)

    assert result.returncode == 1
    assert "dummy.key" in result.stdout
    assert "leaf.crt" in result.stdout
    assert "not-a-real-key" not in result.stdout + result.stderr
    assert "not-a-real-cert" not in result.stdout + result.stderr


def test_material_in_a_directory_that_lost_its_rule_fails(tmp_path: Path) -> None:
    root = make_repo(tmp_path, without_vault_certs_rule())
    certs = root / "vault" / "certs"
    certs.mkdir(parents=True)
    (certs / "vault.key").write_text(PRIVATE_KEY, encoding="utf-8")

    result = run_check(root)

    assert result.returncode == 1
    assert "vault/certs/" in result.stdout
    assert "vault/certs/vault.key" in result.stdout
    assert "not-a-real-key" not in result.stdout + result.stderr

    (root / ".gitignore").write_text(GITIGNORE.read_text(encoding="utf-8"), encoding="utf-8")

    assert run_check(root).returncode == 0


def test_a_missing_env_ignore_rule_fails_naming_only_the_path(tmp_path: Path) -> None:
    root = make_repo(tmp_path, without_env_rules())

    result = run_check(root)

    assert result.returncode == 1
    assert ".env" in result.stdout
    assert ".env.vault" in result.stdout

    (root / ".gitignore").write_text(GITIGNORE.read_text(encoding="utf-8"), encoding="utf-8")

    # Absent files still pass: the rule is what the check protects.
    assert run_check(root).returncode == 0


def test_an_allowlisted_path_passes_and_an_unjustified_entry_fails(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    (root / "dummy.key").write_text(PRIVATE_KEY, encoding="utf-8")
    git(root, "add", "dummy.key")
    git(root, "commit", "--quiet", "-m", "fixture")
    check = load_check()

    assert check.scan(root, {"dummy.key": "fixture for the TLS refusal test"}) == []

    problems = check.scan(root, {"dummy.key": ""})

    assert problems
    assert "without a justification" in problems[0]
    assert "dummy.key" in problems[0]


def test_verbose_names_what_the_check_scans_and_exempts(tmp_path: Path) -> None:
    root = make_repo(tmp_path)

    result = run_check(root, "--verbose")

    assert result.returncode == 0
    assert "allowlist" in result.stdout
    assert ".crt" in result.stdout
