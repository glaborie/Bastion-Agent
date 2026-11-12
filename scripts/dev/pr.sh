#!/usr/bin/env bash
# Open (or re-use) the pull request for the current branch.
#
#   scripts/dev/pr.sh                       # title from the branch's commits
#   scripts/dev/pr.sh --title "..." --body-file body.md
#   scripts/dev/pr.sh --draft --dry-run
#
# The branch must be clean and ahead of origin/master. If a pull request for the
# head already exists it is printed instead of creating a second one. The
# generated body lists the commits and, when the last local gate left a
# summary, its pass/fail table, so the evidence travels with the description.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE="${BASTION_BASE_REF:-origin/master}"
TITLE=""
BODY_FILE=""
DRAFT=0
DRY_RUN=0

die() { echo "pr: $*" >&2; exit 2; }

while (($#)); do
    case "$1" in
        --title)
            [[ $# -ge 2 ]] || die "--title needs a value"
            TITLE="$2"
            shift
            ;;
        --body-file)
            [[ $# -ge 2 ]] || die "--body-file needs a value"
            BODY_FILE="$2"
            shift
            ;;
        --draft) DRAFT=1 ;;
        --dry-run) DRY_RUN=1 ;;
        -h | --help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument '$1'" ;;
    esac
    shift
done

cd "$ROOT"
command -v gh >/dev/null || die "gh is not on PATH"
command -v git >/dev/null || die "git is not on PATH"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[[ "$BRANCH" != "HEAD" ]] || die "detached HEAD; check out a branch first"
[[ "$BRANCH" != "master" ]] || die "refusing to open a pull request from master"

git fetch --quiet origin

if existing="$(gh pr list --head "$BRANCH" --state open --json number,url --jq '.[0].url // empty')" &&
    [[ -n "$existing" ]]; then
    echo "pr: already open: $existing"
    exit 0
fi

[[ -z "$(git status --porcelain)" ]] || die "working tree is dirty; commit or stash first"

AHEAD="$(git rev-list --count "$BASE..HEAD")"
((AHEAD > 0)) || die "no commits ahead of $BASE"

if [[ -z "$TITLE" ]]; then
    if ((AHEAD == 1)); then
        TITLE="$(git log -1 --pretty=%s)"
    else
        die "$AHEAD commits ahead; pass --title (or squash first)"
    fi
fi

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

if [[ -n "$BODY_FILE" ]]; then
    cp "$BODY_FILE" "$TMP_BODY"
else
    {
        echo "## Commits"
        echo
        git log --reverse --pretty='- `%h` %s' "$BASE..HEAD"
        echo
        SUMMARY="artifacts/gate/latest/summary.md"
        if [[ -f "$SUMMARY" ]]; then
            echo "## Last local gate"
            echo
            grep -E '^\| (result|wall / sum|slowest step) ' "$SUMMARY" || true
            echo
            echo "Full table: \`$SUMMARY\` (not committed)."
        else
            echo "## Last local gate"
            echo
            echo "No local gate summary found. Run \`scripts/gate.sh\` before opening."
        fi
    } >"$TMP_BODY"
fi

if ((DRY_RUN)); then
    echo "pr: would open $BRANCH -> ${BASE#origin/}: $TITLE"
    echo "----- body -----"
    cat "$TMP_BODY"
    exit 0
fi

git push --quiet -u origin "$BRANCH"

args=(--base "${BASE#origin/}" --head "$BRANCH" --title "$TITLE" --body-file "$TMP_BODY")
((DRAFT)) && args+=(--draft)
gh pr create "${args[@]}"
