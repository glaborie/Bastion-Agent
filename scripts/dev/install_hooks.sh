#!/usr/bin/env bash
# Install a pre-commit hook that formats-checks the Python files you staged.
#
#   scripts/dev/install_hooks.sh
#
# The hook runs `ruff check` and `ruff format --check` on staged `.py` files
# only, so a mangled import or an unformatted line is caught before it becomes a
# commit rather than after CI rejects it. Remove `.git/hooks/pre-commit` to
# uninstall.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOOK="$(cd "$ROOT" && git rev-parse --git-path hooks)/pre-commit"

mkdir -p "$(dirname "$HOOK")"
cat >"$HOOK" <<'HOOK_EOF'
#!/usr/bin/env bash
# Installed by scripts/dev/install_hooks.sh — safe to delete.
set -euo pipefail

mapfile -t files < <(git diff --cached --name-only --diff-filter=ACMR -- '*.py')
if ((${#files[@]} == 0)); then
    exit 0
fi

runner=(uv run)
[[ -d .venv ]] && runner=(uv run --no-sync)

"${runner[@]}" ruff check "${files[@]}"
"${runner[@]}" ruff format --check "${files[@]}"
HOOK_EOF

chmod +x "$HOOK"
echo "installed $HOOK"
