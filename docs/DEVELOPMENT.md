# Development Workflow

Shortcuts for the parts of the work that are the same every time. Each script is
safe to re-run and prints what it did; none of them replace the gates.

## Start an item

```bash
scripts/dev/worktree.sh start IDEA-030
```

Creates a worktree from `origin/master` under
`${BASTION_WORKTREE_ROOT:-~/.local/share/bastion-agent/worktrees}` on branch
`idea-030-<slug>`, symlinks the repository `.env` (so compose and the test suite
work without `--env-file`), installs the locked dependencies, marks the item
`active` and regenerates the Board **inside the worktree**. The path is the last
line it prints; move the session there next.

Do not implement an item in the main checkout: the worktree is what keeps the
branch, the status change and the evidence together.

## Check before opening

```bash
scripts/gate.sh --changed        # pylint + pytest narrowed to the diff
scripts/gate.sh                  # everything, including the compose renders
scripts/gate.sh --no-infra       # skip the docker compose config step
```

`--changed` never runs nothing: when a shared file changed (`conftest.py`,
`settings.py`, `db/models.py`, `docs/tools/v1.json`) or no test file maps to the
diff, it runs the full suite. Pytest runs under xdist only when
`TEST_DATABASE_URL` is unset, because the database fixtures truncate tables
shared by every module.

## Open the pull request

```bash
scripts/dev/pr.sh --dry-run      # print the generated body
scripts/dev/pr.sh                # push and create, or reuse an open PR
```

The body lists the commits and the last gate summary. A pull request that is
already open for the branch is printed instead of duplicated, and `master` is
refused.

## Clean up after merge

```bash
scripts/dev/cleanup.sh --dry-run
scripts/dev/cleanup.sh
```

Removes worktrees and deletes local and remote branches only where a pull
request is merged or the branch is fully merged into `origin/master`. It leaves
alone anything with an open PR, uncommitted work, commits beyond the base with
no merged PR, and the branch you are standing on. Certificate material owned by
container uids is cleared through a throwaway container instead of escalating
the script.

## Optional hook

```bash
scripts/dev/install_hooks.sh
```

Adds a pre-commit hook that runs `ruff check` and `ruff format --check` on the
Python files you staged, so a mangled import or an unformatted line fails before
it becomes a commit.

## See also

- `docs/TROUBLESHOOTING.md` — environment failures that cost time before they
  were diagnosed.
- `AGENTS.md` — the rules an agent session follows, including the worktree and
  PR discipline above.
