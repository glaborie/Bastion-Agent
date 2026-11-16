"""Contract tests for the repository tooling in scripts/dev."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLEANUP = ROOT / "scripts" / "dev" / "cleanup.sh"


def tool(name: str) -> str:
    path = shutil.which(name)
    assert path is not None, f"{name} is not on PATH"
    return path


GIT = tool("git")
BASH = tool("bash")


def git(*args: str, cwd: Path) -> str:
    result = subprocess.run([GIT, *args], cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout


def script(root: Path, *args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run the checkout's cleanup.sh, with `gh` reporting every branch as merged.

    A merged pull request is the only state that removes a branch, so the stub is
    what makes the destructive path reachable without a real remote.
    """
    env = dict(os.environ, PATH=f"{root / 'bin'}{os.pathsep}{os.environ['PATH']}")
    return subprocess.run(
        [BASH, "scripts/dev/cleanup.sh", *args],
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def build_repo(tmp_path: Path) -> tuple[Path, Path, Path]:
    """An origin with a main checkout standing on one branch and two linked
    worktrees: the caller's, and one the script is expected to remove."""
    origin = tmp_path / "origin.git"
    subprocess.run([GIT, "init", "--bare", "-b", "master", str(origin)], check=True)
    main = tmp_path / "main"
    subprocess.run([GIT, "clone", str(origin), str(main)], check=True)
    for key, value in (("user.email", "dev@example.com"), ("user.name", "dev")):
        git("config", key, value, cwd=main)

    (main / "scripts" / "dev").mkdir(parents=True)
    shutil.copy(CLEANUP, main / "scripts" / "dev" / "cleanup.sh")
    (main / "file.txt").write_text("base\n")
    git("add", "-A", cwd=main)
    git("commit", "-m", "base", cwd=main)
    git("push", "-u", "origin", "master", cwd=main)

    removed = tmp_path / "linked-removed"
    git("worktree", "add", "-b", "idea-removed", str(removed), "master", cwd=main)
    (removed / "removed.txt").write_text("removed\n")
    git("add", "-A", cwd=removed)
    git("commit", "-m", "removed", cwd=removed)
    git("push", "-u", "origin", "idea-removed", cwd=removed)

    caller = tmp_path / "linked-caller"
    git("worktree", "add", "-b", "idea-caller", str(caller), "master", cwd=main)
    (caller / "caller.txt").write_text("caller\n")
    git("add", "-A", cwd=caller)
    git("commit", "-m", "caller", cwd=caller)
    git("push", "-u", "origin", "idea-caller", cwd=caller)

    # The incident's precondition: the main checkout sits on a branch of its own,
    # so removing that branch's worktree removes the main checkout and its .git.
    git("checkout", "-b", "idea-main", cwd=main)
    (main / "main.txt").write_text("main\n")
    git("add", "-A", cwd=main)
    git("commit", "-m", "main branch", cwd=main)
    git("push", "-u", "origin", "idea-main", cwd=main)

    (tmp_path / "bin").mkdir()
    gh = tmp_path / "bin" / "gh"
    gh.write_text("#!/bin/sh\necho MERGED\n")
    gh.chmod(0o755)
    return main, removed, caller


def test_cleanup_from_a_linked_worktree_never_removes_the_main_worktree(tmp_path: Path) -> None:
    main, removed, caller = build_repo(tmp_path)

    script(tmp_path, cwd=caller)

    assert (main / ".git").is_dir()
    assert (main / "file.txt").exists()
    assert git("branch", "--list", "idea-main", cwd=main).strip()
    assert not removed.exists()
    assert not git("branch", "--list", "idea-removed", cwd=main).strip()


def test_dry_run_names_the_main_worktree_only_as_excluded(tmp_path: Path) -> None:
    main, removed, caller = build_repo(tmp_path)

    output = script(tmp_path, "--dry-run", cwd=caller).stdout

    assert f"main worktree (never removed): {main}" in output
    assert f"idea-main (main worktree {main} is never removed)" in output
    assert f"would remove: idea-removed (worktree {removed})" in output
    assert (main / ".git").is_dir()
    assert removed.exists()
