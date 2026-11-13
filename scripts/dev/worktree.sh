#!/usr/bin/env bash
# Start one backlog item: worktree from origin/master, branch, .env, deps.
#
#   scripts/dev/worktree.sh start IDEA-030            # title-derived branch slug
#   scripts/dev/worktree.sh start IDEA-030 --slug ws  # explicit slug
#   scripts/dev/worktree.sh start IDEA-030 --base origin/master
#
# The worktree is created from the base with a fresh branch, the repository
# .env is symlinked in (so compose and the test suite work without --env-file),
# locked dependencies are installed, and the item is marked `active` with the
# Board regenerated inside that worktree. The item therefore travels with its
# own branch instead of dirtying the checkout you are standing in.
#
# Prints the worktree path as the last line: move the session there next.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE="${BASTION_BASE_REF:-origin/master}"
WORKTREE_ROOT="${BASTION_WORKTREE_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/bastion-agent/worktrees}"

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; }

die() { echo "worktree: $*" >&2; exit 2; }

slugify() {
    printf '%s' "$1" |
        tr '[:upper:]' '[:lower:]' |
        sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' |
        cut -c1-40 |
        sed -E 's/-+$//'
}

[[ $# -ge 1 ]] || { usage; exit 2; }
command="$1"
shift

case "$command" in
    start) ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown command '$command' (try --help)" ;;
esac

ITEM_ID="${1:-}"
[[ "$ITEM_ID" =~ ^IDEA-[0-9]{3}$ ]] || die "expected an item id like IDEA-030"
shift

SLUG=""
while (($#)); do
    case "$1" in
        --slug)
            [[ $# -ge 2 ]] || die "--slug needs a value"
            SLUG="$2"
            shift
            ;;
        --base)
            [[ $# -ge 2 ]] || die "--base needs a git ref"
            BASE="$2"
            shift
            ;;
        *) die "unknown argument '$1'" ;;
    esac
    shift
done

command -v git >/dev/null || die "git is not on PATH"
command -v uv >/dev/null || die "uv is not on PATH"

git -C "$ROOT" rev-parse --verify -q "$BASE" >/dev/null || die "base ref '$BASE' not found (fetch it first)"

# Title comes from the item file so the branch name and the item cannot drift.
ITEM_FILE="$(compgen -G "$ROOT/backlog/items/${ITEM_ID}-*.md" | head -n1)"
[[ -n "$ITEM_FILE" ]] || die "$ITEM_ID has no file under backlog/items/"
TITLE="$(grep -m1 "^### ${ITEM_ID}: " "$ITEM_FILE" | sed -E "s/^### ${ITEM_ID}: //")" ||
    die "$ITEM_ID has no title line in $ITEM_FILE"
[[ -n "$TITLE" ]] || die "$ITEM_ID has no title line"

if [[ -z "$SLUG" ]]; then
    SLUG="$(slugify "$TITLE")"
fi
[[ -n "$SLUG" ]] || die "could not derive a slug; pass --slug"

BRANCH="${ITEM_ID,,}-${SLUG}"
DIR="$WORKTREE_ROOT/$BRANCH"

git -C "$ROOT" fetch --quiet origin
git -C "$ROOT" show-ref --verify --quiet "refs/heads/$BRANCH" && die "branch $BRANCH already exists"
[[ -e "$DIR" ]] && die "$DIR already exists"

mkdir -p "$WORKTREE_ROOT"
git -C "$ROOT" worktree add --quiet -b "$BRANCH" "$DIR" "$BASE"
echo "worktree: $DIR ($BRANCH from $BASE)"

# Compose and the test suite read .env from the working directory; a symlink
# keeps one source of truth and removes the --env-file tax in every worktree.
if [[ -f "$ROOT/.env" && ! -e "$DIR/.env" ]]; then
    ln -s "$ROOT/.env" "$DIR/.env"
    echo "worktree: linked .env"
fi

if [[ -f "$DIR/pyproject.toml" ]]; then
    (cd "$DIR" && uv sync --quiet --frozen --group dev)
    echo "worktree: dependencies installed"
fi

# Claim the item inside the worktree so the status change travels with its
# branch. Only the item's own file is touched, so parallel worktrees never edit
# the same path; the rendered BACKLOG.md is generated and untracked.
ITEM_FILE="$DIR/backlog/items/$(basename "$ITEM_FILE")"
if [[ -f "$ITEM_FILE" ]]; then
    python3 - "$ITEM_FILE" <<'PY'
import datetime as dt
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
today = dt.date.today().isoformat()
text = re.sub(r"^- status: .*$", "- status: active", text, count=1, flags=re.M)
text = re.sub(r"^- updated: .*$", f"- updated: {today}", text, count=1, flags=re.M)
path.write_text(text, encoding="utf-8")
print(f"worktree: {path.name} marked active")
PY
    (cd "$DIR" && uv run --no-sync python scripts/check_backlog.py --write >/dev/null)
fi

echo "$DIR"
