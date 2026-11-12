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
# The current branch and master are never removed.
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

# branch -> worktree path (empty when the branch is not checked out anywhere)
declare -A worktree_of=()
while IFS= read -r line; do
    case "$line" in
        "worktree "*) wt_path="${line#worktree }" ;;
        "branch refs/heads/"*) worktree_of["${line#branch refs/heads/}"]="$wt_path" ;;
    esac
done < <(git worktree list --porcelain)

pr_state() {
    # empty = no pull request, otherwise OPEN / MERGED / CLOSED
    gh pr list --head "$1" --state all --json state --jq '[.[].state] | join(",")' 2>/dev/null || true
}

remove_worktree() {
    local path="$1"
    [[ -n "$path" && "$path" != "$ROOT" ]] || return 0
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

for branch in $(git for-each-ref --format='%(refname:short)' refs/heads/); do
    [[ "$branch" == "master" || "$branch" == "$current" ]] && continue
    path="${worktree_of[$branch]:-}"
    states="$(pr_state "$branch")"

    if [[ ",$states," == *",OPEN,"* ]]; then
        skipped+=("$branch (open pull request)")
        continue
    fi

    merged_pr=0
    [[ ",$states," == *",MERGED,"* ]] && merged_pr=1
    ancestor=0
    git merge-base --is-ancestor "refs/heads/$branch" "$BASE" 2>/dev/null && ancestor=1

    if ((!merged_pr && !ancestor)); then
        skipped+=("$branch (unmerged, no merged pull request)")
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
