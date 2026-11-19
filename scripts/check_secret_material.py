#!/usr/bin/env python3
"""Fail when certificate or key material becomes trackable.

Two directions are checked, because the 2026-11-14 incident defeated the
second while passing the first:

* a path matching ``MATERIAL_SUFFIXES`` is tracked by git;
* a file on disk is *trackable* — untracked and not ignored — because its
  directory lost its ``.gitignore`` rule (that is how ``vault/certs/vault.key``
  sat one ``git add -A`` away from master);
* each generated-material directory in ``GENERATED_DIRS`` still has an ignore
  rule, so the rule cannot disappear without a red check.

An entry in ``ALLOWLIST`` exempts a path, and every entry must carry its
justification; an entry without one fails. ``--verbose`` prints the allowlist.

    uv run python scripts/check_secret_material.py [--verbose]

Exit codes: ``0`` clean, ``1`` material is trackable or a rule is missing,
``2`` the repository root or its ``.gitignore`` cannot be read.

Honest limit: this matches extensions and ignore rules. A private key copied to
``notes.txt``, pasted into a Markdown file, or renamed to an extension outside
``MATERIAL_SUFFIXES`` is invisible here. It raises the floor; review remains the
control for content.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
MATERIAL_SUFFIXES = (".crt", ".key", ".pem", ".p12", ".pfx", ".jks")
GENERATED_DIRS = ("pki/", "secrets/", "vault/certs/")
#: Materialised env files: `.env` is hand-edited and `.env.vault` is written by
#: `make vault-export`. Both must stay ignored even though they are absent on a
#: fresh clone, so the rule cannot disappear without a red check (IDEA-076).
MATERIALISED_ENV_FILES = (".env", ".env.vault")

# Tracked fixtures that must stay committed, path -> why it is safe.
# Keep this empty until a test genuinely needs key material in the tree; a
# fixture that can be generated at test time belongs in a temp directory.
ALLOWLIST: dict[str, str] = {}


class RepositoryError(RuntimeError):
    """Git or .gitignore could not be read."""


def _git(root: Path, *args: str) -> list[str]:
    try:
        result = subprocess.run(  # noqa: S603 - fixed git CLI, arguments built here
            ["git", "-C", str(root), *args],  # noqa: S607 - resolved from PATH by design
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RepositoryError(f"git {' '.join(args)} failed in {root}: {exc}") from exc
    return [line for line in result.stdout.splitlines() if line]


def is_material(path: str) -> bool:
    """True when the path carries a certificate or key extension."""
    return path.lower().endswith(MATERIAL_SUFFIXES)


def ignore_rules(root: Path) -> list[str]:
    path = root / ".gitignore"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RepositoryError(f"cannot read {path}: {exc}") from exc
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def tracked_material(root: Path, allowlist: Mapping[str, str] | None = None) -> list[str]:
    """Tracked certificate or key paths that no allowlist entry exempts."""
    exempt = ALLOWLIST if allowlist is None else allowlist
    return [p for p in _git(root, "ls-files") if is_material(p) and p not in exempt]


def untracked_material(root: Path, allowlist: Mapping[str, str] | None = None) -> list[str]:
    """Material on disk that git would stage: untracked and not ignored."""
    exempt = ALLOWLIST if allowlist is None else allowlist
    others = _git(root, "ls-files", "--others", "--exclude-standard")
    return [p for p in others if is_material(p) and p not in exempt]


def missing_ignore_rules(root: Path) -> list[str]:
    """Generated-material directories whose .gitignore rule is gone."""
    rules = set(ignore_rules(root))
    return [d for d in GENERATED_DIRS if d not in rules and d not in {r.rstrip("/") for r in rules}]


def ignored_path(root: Path, path: str) -> bool:
    """True when git would ignore ``path`` (the path need not exist)."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed git CLI, argument built here
            ["git", "-C", str(root), "check-ignore", "-q", path],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RepositoryError(f"git check-ignore failed in {root}: {exc}") from exc
    if result.returncode not in (0, 1):
        raise RepositoryError(f"git check-ignore failed in {root}: rc={result.returncode}")
    return result.returncode == 0


def unignored_env_files(root: Path) -> list[str]:
    """Materialised env files whose ignore rule is gone."""
    return [name for name in MATERIALISED_ENV_FILES if not ignored_path(root, name)]


def scan(root: Path, allowlist: Mapping[str, str] | None = None) -> list[str]:
    """Return one message per problem; messages name paths, never content."""
    exempt = ALLOWLIST if allowlist is None else allowlist
    problems = [
        f"tracked certificate or key material: {p} — untrack it and rotate whatever it protects"
        for p in tracked_material(root, exempt)
    ]
    problems += [
        f"untracked certificate or key material: {p} — nothing in .gitignore covers it, "
        "so a plain `git add -A` would commit it"
        for p in untracked_material(root, exempt)
    ]
    problems += [
        f"generated material directory is not ignored: {d} — .gitignore is missing the `{d}` rule"
        for d in missing_ignore_rules(root)
    ]
    problems += [
        f"materialised env file is not ignored: {p} — .gitignore is missing the rule, "
        "so a plain `git add -A` would commit it"
        for p in unignored_env_files(root)
    ]
    problems += [
        f"allowlist entry without a justification: {p} — state why the material is safe to commit"
        for p, reason in exempt.items()
        if not reason.strip()
    ]
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail when certificate or key material becomes trackable."
    )
    parser.add_argument(
        "--root", type=Path, default=None, help="repository root (default: this checkout)"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="print the allowlist and what was scanned"
    )
    args = parser.parse_args(argv)
    root: Path = args.root or DEFAULT_ROOT

    if args.verbose:
        print(f"secret material: scanning {root}")
        print(
            f"secret material: suffixes {', '.join(MATERIAL_SUFFIXES)}; "
            f"generated dirs {', '.join(GENERATED_DIRS)}; "
            f"env files {', '.join(MATERIALISED_ENV_FILES)}"
        )
        if ALLOWLIST:
            for path, reason in sorted(ALLOWLIST.items()):
                print(f"secret material: allowlisted {path} — {reason}")
        else:
            print("secret material: allowlist is empty")

    try:
        problems = scan(root)
    except RepositoryError as exc:
        print(f"check_secret_material: {exc}", file=sys.stderr)
        return 2

    for problem in problems:
        print(problem)
    if problems:
        print(f"secret material: {len(problems)} problem(s); the gate protects certs and keys")
        return 1
    print("OK: no tracked certificate or key material, generated dirs ignored")
    return 0


if __name__ == "__main__":
    sys.exit(main())
