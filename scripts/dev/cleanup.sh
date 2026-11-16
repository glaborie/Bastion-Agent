#!/usr/bin/env bash
# Remove worktrees and branches whose pull request is merged.
#
#   scripts/dev/cleanup.sh --dry-run   # print the plan, change nothing
#   scripts/dev/cleanup.sh             # remove and prune
#
# A branch is only touched when it is safe:
#   * an open pull request for it -> skipped;
#   * a merged pull request for it -> removed (covers squash merges);
#   * otherwise it must be fully merged into origin/master -> removed;
#   * anything else (unmerged, no PR) -> reported and left alone.
# The main worktree, the current branch and master are never removed, whichever
# directory the script is run from.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE="${BASTION_BASE_REF:-origin/master}"
DRY_RUN=0

die() { echo "cleanup: $*" >&2; exit 2; }

while (($#)); do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        -h | --help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument '$1'" ;;
    esac
    shift
done

cd "$ROOT"
command -v git >/dev/null || die "git is not on PATH"
git fetch --quiet --prune origin

current="$(git rev-parse --abbrev-ref HEAD)"
[[ "$current" != "HEAD" ]] || die "detached HEAD; check out master first"

canon() { (cd "$1" 2>/dev/null && pwd -P) || printf '%s\n' "$1"; }

# The main worktree is the first entry of `git worktree list`; it owns the shared
# .git, so deleting it destroys every linked worktree. Never derive it from the
# script's own directory: an agent runs this from a linked worktree.
main_worktree=""
declare -A worktree_of=()
while IFS= read -r line; do
    case "$line" in
        "worktree "*) wt_path="${line#worktree }"; [[ -n "$main_worktree" ]] || main_worktree="$wt_path" ;;
        "branch refs/heads/"*) worktree_of["${line#branch refs/heads/}"]="$wt_path" ;;
    esac
done < <(git worktree list --porcelain)
[[ -n "$main_worktree" ]] || die "cannot identify the main worktree"
main_worktree="$(canon "$main_worktree")"

# A worktree is deletable only when it is a linked one: a linked worktree has a
# .git file, the main checkout has a .git directory.
removable() {
    local path="$1"
    [[ -n "$path" ]] || return 0
    [[ "$(canon "$path")" != "$main_worktree" && ! -d "$path/.git" ]]
}

pr_state() {
    # empty = no pull request, otherwise OPEN / MERGED / CLOSED
    gh pr list --head "$1" --state all --json state --jq '[.[].state] | join(",")' 2>/dev/null || true
}

remove_worktree() {
    local path="$1"
    [[ -n "$path" ]] || return 0
    removable "$path" || return 1
    if git worktree remove --force "$path" 2>/dev/null; then
        return 0
    fi
    # Certificate material under a worktree's pki/ is owned by container uids;
    # clear it through a container rather than escalating the whole script.
    if [[ -d "$path" ]]; then
        docker run --rm -v "$path:/cleanup" alpine sh -c 'rm -rf /cleanup/* /cleanup/.[!.]*' >/dev/null 2>&1 || true
        rm -rf "$path" 2>/dev/null || true
    fi
    git worktree prune
}

removed=0
skipped=()
((DRY_RUN)) && echo "main worktree (never removed): $main_worktree"

for branch in $(git for-each-ref --format='%(refname:short)' refs/heads/); do
    [[ "$branch" == "master" || "$branch" == "$current" ]] && continue
    path="${worktree_of[$branch]:-}"
    states="$(pr_state "$branch")"

    if [[ ",$states," == *",OPEN,"* ]]; then
        skipped+=("$branch (open pull request)")
        continue
    fi

    # Uncommitted work always wins: a worktree can hold a half-finished item,
    # and a branch that merely sits on the base commit looks "merged" to git.
    if [[ -n "$path" && -n "$(git -C "$path" status --porcelain 2>/dev/null)" ]]; then
        skipped+=("$branch (uncommitted changes in $path)")
        continue
    fi

    ahead="$(git rev-list --count "$BASE..refs/heads/$branch")"
    merged_pr=0
    [[ ",$states," == *",MERGED,"* ]] && merged_pr=1
    ancestor=0
    ((ahead > 0)) && git merge-base --is-ancestor "refs/heads/$branch" "$BASE" 2>/dev/null && ancestor=1

    if ((!merged_pr && !ancestor)); then
        if ((ahead == 0)); then
            skipped+=("$branch (no commits beyond $BASE, no pull request)")
        else
            skipped+=("$branch (unmerged, no merged pull request)")
        fi
        continue
    fi

    if ! removable "$path"; then
        skipped+=("$branch (main worktree $path is never removed)")
        continue
    fi

    if ((DRY_RUN)); then
        echo "would remove: $branch${path:+ (worktree $path)}${states:+ [PR: $states]}"
        ((removed += 1))
        continue
    fi

    echo "removing: $branch${path:+ (worktree $path)}"
    remove_worktree "$path"
    git branch -D "$branch" >/dev/null
    if git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
        git push --quiet origin --delete "$branch" >/dev/null || true
    fi
    ((removed += 1))
done

((DRY_RUN)) || git worktree prune

if ((${#skipped[@]})); then
    echo
    echo "left alone:"
    printf '  %s\n' "${skipped[@]}"
fi

if ((DRY_RUN)); then
    echo
    echo "cleanup: $removed branch(es) would be removed (dry run)"
else
    echo "cleanup: $removed branch(es) removed"
fi
