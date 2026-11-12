#!/usr/bin/env bash
# Publish the repository's wiki/ directory to the GitHub wiki.
#
# GitHub keeps a wiki in its own Git repository (<owner>/<repo>.wiki.git), so
# nothing in this repository's history reaches the wiki on its own. This script
# mirrors wiki/ there: same page names, no extra pages, one commit per run, and
# no commit at all when nothing changed.
#
#   scripts/sync_wiki.sh                     # dry run: show what would be published
#   scripts/sync_wiki.sh --push              # mirror, commit and push
#   scripts/sync_wiki.sh --push --message "docs(wiki): ..."
#
# Environment:
#   WIKI_REMOTE   wiki repository URL (default: derived from origin)
#   WIKI_BRANCH   branch to push to (default: master)
#   WIKI_TOKEN    token for the clone and push; defaults to GH_TOKEN or
#                 GITHUB_TOKEN, then to the ambient git credentials (for example
#                 `gh auth setup-git`). CI passes WIKI_SYNC_TOKEN here.
#
# Exit codes: 0 up to date or published, 1 a git failure, 2 usage or precondition.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PUSH=0
MESSAGE=""

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; }

while (($#)); do
    case "$1" in
        --push) PUSH=1 ;;
        --message)
            [[ $# -ge 2 ]] || { echo "sync_wiki: --message needs a value" >&2; exit 2; }
            MESSAGE="$2"
            shift
            ;;
        -h | --help) usage; exit 0 ;;
        *) echo "sync_wiki: unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

[[ -d wiki ]] || { echo "sync_wiki: no wiki/ directory" >&2; exit 2; }

mapfile -t pages < <(find wiki -maxdepth 1 -name '*.md' -printf '%f\n' | sort)
((${#pages[@]})) || { echo "sync_wiki: wiki/ holds no Markdown pages" >&2; exit 2; }

if [[ -z ${WIKI_REMOTE:-} ]]; then
    origin="$(git config --get remote.origin.url)"
    case "$origin" in
        git@github.com:*) owner_repo="${origin#git@github.com:}" ;;
        https://github.com/*) owner_repo="${origin#https://github.com/}" ;;
        *) echo "sync_wiki: cannot derive the wiki URL from origin ($origin); set WIKI_REMOTE" >&2; exit 2 ;;
    esac
    WIKI_REMOTE="https://github.com/${owner_repo%.git}.wiki.git"
fi
BRANCH="${WIKI_BRANCH:-master}"
TOKEN="${WIKI_TOKEN:-${GH_TOKEN:-${GITHUB_TOKEN:-}}}"

# Authenticate the clone and the push without writing the token to the remote
# URL or to .git/config. The extraheader applies only to github.com.
git_auth=()
if [[ -n $TOKEN ]]; then
    basic="$(printf 'x-access-token:%s' "$TOKEN" | base64 | tr -d '\n')"
    git_auth=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic ${basic}")
elif command -v gh >/dev/null 2>&1; then
    git_auth=(-c credential.helper='!gh auth git-credential')
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
dest="$tmp/wiki"

echo "wiki: cloning $WIKI_REMOTE"
git "${git_auth[@]}" clone --quiet --branch "$BRANCH" "$WIKI_REMOTE" "$dest"

# Mirror, do not merge: a page that left wiki/ leaves the published wiki too.
find "$dest" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp wiki/*.md "$dest"/

if [[ -z $(git -C "$dest" status --porcelain) ]]; then
    echo "wiki: up to date"
    exit 0
fi

git -C "$dest" add --all
git -C "$dest" --no-pager diff --cached --stat

if ((!PUSH)); then
    echo "wiki: dry run; pass --push to publish"
    exit 0
fi

message="${MESSAGE:-docs(wiki): sync from $(git -C "$ROOT" rev-parse --short HEAD)}"
git -C "$dest" \
    -c user.name="${GIT_AUTHOR_NAME:-github-actions[bot]}" \
    -c user.email="${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}" \
    commit --quiet -m "$message"
git -C "$dest" "${git_auth[@]}" push --quiet origin "HEAD:$BRANCH"
echo "wiki: published $(git -C "$dest" rev-parse --short HEAD)"
