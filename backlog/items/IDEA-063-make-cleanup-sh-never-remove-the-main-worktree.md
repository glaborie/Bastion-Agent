### IDEA-063: Make cleanup.sh never remove the main worktree

- status: ready
- priority: P1
- phase: v0.3
- area: tooling
- tags: git, worktree, automation
- depends-on: -
- spec: -
- created: 2026-11-16
- updated: 2026-11-16
- source: incident 2026-11-16, running scripts/dev/cleanup.sh from a worktree deleted /home/glaborie/projects/Bastion-Agent

**Problem**

`scripts/dev/cleanup.sh` computes `ROOT` from its own path and excludes only that
directory when removing a worktree (`remove_worktree` returns early when
`$path == $ROOT`). Run from a linked worktree — which is the normal place an
agent runs it — `ROOT` is the worktree, not the main checkout, so the main
worktree entry from `git worktree list` is eligible. On 2026-11-16 the branch
`backlog/cert-material-guard` was judged merged and the script ran
`git worktree remove --force /home/glaborie/projects/Bastion-Agent`: it deleted
the main checkout and the shared `.git` directory (object database, worktree
metadata and the untracked `.env`). Every linked worktree was left with a
dangling `gitdir:` pointer and the repo had to be re-cloned from origin; the
`.env` was recovered separately from the Vault volume. `git worktree remove`
documents that the main worktree cannot be removed, but the script's fallback
(`rm -rf "$path"`) made the destructive path succeed.

**Outcome**

`cleanup.sh` can never remove the main worktree, from any directory, and its
`--dry-run` output names the main checkout only as excluded. The script still
removes merged linked worktrees and their branches as before.

**Acceptance**

- [ ] Running `scripts/dev/cleanup.sh` from a linked worktree never removes the
      main worktree: the main path and its `.git` directory survive, and the
      merged linked worktree is still removed
- [ ] The exclusion set is derived from `git worktree list --porcelain` (the
      first entry, or every entry that is not a linked worktree) rather than from
      the script's own directory, and the destructive fallback refuses a path
      that contains an active `.git` directory or is the main worktree
- [ ] A test builds a throwaway repository with a main worktree and one merged
      linked worktree, runs the script from inside the linked worktree, and
      asserts the main tree and its `.git` still exist and the linked worktree is
      gone
- [ ] `scripts/dev/worktree.sh`/`cleanup.sh` keep their existing `--help` text
      and the gate stays green (`uv run python scripts/check_backlog.py --check`
      at minimum; the full `scripts/gate.sh` when the fix lands)

**Notes**

- Incident 2026-11-16: the main checkout was restored by cloning
  `glaborie/Bastion-Agent` again at `8bd8d51`; every worktree branch had a merged
  pull request and no file existed only in a worktree, so no source was lost.
  `.env` was recovered from the existing Vault volume and its Postgres password
  verified against the surviving `bastion-agent_pgdata` volume.
- No ADR governs repository tooling; this is `area: tooling`, `spec: -`. A short
  AGENTS.md sentence may be the only documentation the fix needs, but that is an
  implementation choice.
- Related but different: IDEA-041 owns one-item-per-file backlog storage and the
  worktree claim discipline; this item is only the cleanup script's main-worktree
  exclusion and its destructive fallback.
