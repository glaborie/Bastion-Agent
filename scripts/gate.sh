#!/usr/bin/env bash
# Run every repository gate and print one metrics table plus a one-line verdict.
#
# The gate list is the one in .opencode/commands/next.md §5 and README
# "Verification"; this script only sequences it, it never weakens a check.
# Steps run in a bounded pool (pytest first, since it is the long pole). Each run
# leaves artifacts/gate/<run>/ with one log per step plus summary.md; the
# bookkeeping that steers the pool lives in a temporary directory and is deleted
# on exit. artifacts/gate/latest points at the newest run.
#
#   scripts/gate.sh                 # lint, types, policy, unit tests
#   scripts/gate.sh --evals         # ... plus the deterministic DeepEval gate
#   scripts/gate.sh --integration   # ... plus the database-backed tests
#   scripts/gate.sh --jobs 2        # cap the pool (1 = serial; default: cores-1, max 4)
#   scripts/gate.sh --no-tests      # skip pytest (docs-only changes)
#   scripts/gate.sh --verbose       # stream each step, prefixed with its name
#   scripts/gate.sh --changed       # pylint and pytest only what changed against origin/master
#   scripts/gate.sh --no-infra      # skip the compose-config validation step
#   scripts/gate.sh --pytest-workers 0   # disable xdist (default: auto without a DB)
#   scripts/gate.sh --changed --base origin/release   # ... against another ref
#
# `run_evals.py` runs the eval suites through pytest itself, so it is never
# pooled with the pytest step: it runs alone once the pool drains.
#
# Exit codes: 0 all gates passed, 1 a gate failed, 2 usage or precondition error.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

RUN_TESTS=1
RUN_EVALS=0
INTEGRATION=0
VERBOSE=0
JOBS=""
CHANGED_ONLY=0
CHANGED_BASE="origin/master"
RUN_INFRA=1
PYTEST_WORKERS=""

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; }

while (($#)); do
    case "$1" in
        --no-tests) RUN_TESTS=0 ;;
        --evals) RUN_EVALS=1 ;;
        --integration) INTEGRATION=1 ;;
        --verbose) VERBOSE=1 ;;
        --changed) CHANGED_ONLY=1 ;;
        --no-infra) RUN_INFRA=0 ;;
        --pytest-workers)
            [[ $# -ge 2 ]] || { echo "gate: --pytest-workers needs a number or 'auto'" >&2; exit 2; }
            PYTEST_WORKERS="$2"
            shift
            ;;
        --base)
            [[ $# -ge 2 ]] || { echo "gate: --base needs a git ref" >&2; exit 2; }
            CHANGED_BASE="$2"
            shift
            ;;
        --serial) JOBS=1 ;;
        --jobs)
            [[ $# -ge 2 ]] || { echo "gate: --jobs needs a number" >&2; exit 2; }
            JOBS="$2"
            shift
            ;;
        -h | --help) usage; exit 0 ;;
        *) echo "gate: unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

command -v uv >/dev/null || { echo "gate: uv is not on PATH" >&2; exit 2; }

if ((INTEGRATION)) && [[ -z "${TEST_DATABASE_URL:-}" ]]; then
    echo "gate: --integration needs TEST_DATABASE_URL (see README 'Verification')" >&2
    exit 2
fi

if [[ -z "$JOBS" ]]; then
    cores=$(nproc 2>/dev/null || echo 2)
    JOBS=$((cores - 1))
    ((JOBS < 1)) && JOBS=1
    ((JOBS > 4)) && JOBS=4
fi
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "gate: --jobs must be a positive integer" >&2; exit 2; }

# CI pins these; keep local runs quiet and offline unless the caller says otherwise.
export OTEL_ENABLED="${OTEL_ENABLED:-false}"
export PYTHONUNBUFFERED=1

if ((INTEGRATION)); then
    PYTEST_FLAGS='-ra'
    TEST_MODE=all
else
    # The unit selection matches .opencode/commands/next.md §5.
    PYTEST_FLAGS='-q -m "not integration"'
    TEST_MODE=unit
fi

# Parallel pytest only when no shared database is in play. The DB fixtures
# truncate tables per module, so two workers against one test database would
# clobber each other. `--dist loadfile` keeps each file on a single worker.
if [[ -z "$PYTEST_WORKERS" ]]; then
    if [[ -n "${TEST_DATABASE_URL:-}" ]]; then
        PYTEST_WORKERS=0
    else
        PYTEST_WORKERS=auto
    fi
fi
[[ "$PYTEST_WORKERS" == "auto" || "$PYTEST_WORKERS" =~ ^[1-9][0-9]*$ ]] ||
    { echo "gate: --pytest-workers must be 'auto' or a positive integer" >&2; exit 2; }
XDIST=""
[[ "$PYTEST_WORKERS" != "0" ]] && XDIST="-n $PYTEST_WORKERS --dist loadfile"

STAMP="$(date +%Y%m%d-%H%M%S)"
LOGDIR="artifacts/gate/$STAMP"
mkdir -p "$LOGDIR"

# Per-step status and timing are bookkeeping, not evidence: keep them in $TMPDIR
# so the run directory only holds logs a human might actually read.
STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/bastion-gate.XXXXXX") || exit 2
trap 'rm -rf "$STATE_DIR"' EXIT

NAMES=()
CMDS=()
LAUNCH_ORDER=()

add_step() {
    NAMES+=("$1")
    CMDS+=("$2")
}

# Declared in canonical display order; launched in LAUNCH_ORDER (longest first).

# Pylint targets: the whole tree by default. `--changed` narrows it to the .py
# files this branch touches, and falls back to the whole tree when pylint's own
# configuration or pin moved, because those changes are only meaningful against
# every file. The same rule runs in CI (.github/workflows/ci.yml).
PYLINT_TARGETS=(settings.py logging_setup.py telemetry.py db gateway agent tests scripts)
PYTEST_TARGETS=()
if ((CHANGED_ONLY)); then
    git rev-parse --verify -q "$CHANGED_BASE" >/dev/null || {
        echo "gate: --changed base ref '$CHANGED_BASE' not found (fetch it or pass --base)" >&2
        exit 2
    }
    # Diff the working tree, not just HEAD: a local run usually lints edits that
    # are not committed yet. Untracked files count too.
    mapfile -t changed_files < <(
        { git diff --name-only --diff-filter=ACMR "$CHANGED_BASE";
          git ls-files --others --exclude-standard; } | sort -u
    )
    if printf '%s\n' "${changed_files[@]}" |
        grep -qE '^(pyproject\.toml|pylintrc|\.pylintrc|\.github/workflows/ci\.yml)$'; then
        echo "gate: pylint config or pin changed against $CHANGED_BASE; linting the whole tree"
    else
        mapfile -t PYLINT_TARGETS < <(printf '%s\n' "${changed_files[@]}" | grep -E '\.py$' || true)
        echo "gate: pylint narrowed to ${#PYLINT_TARGETS[@]} changed file(s) against $CHANGED_BASE"
    fi

    # Tests: same idea, stricter default. A file whose behaviour is shared by
    # many suites (conftest, models, settings, the tool catalogue) forces the
    # full suite; otherwise run the test files named after the changed modules,
    # and fall back to everything rather than to nothing.
    PYTEST_TARGETS=()
    shared=""
    for f in "${changed_files[@]}"; do
        case "$f" in
            conftest.py | tests/conftest.py | settings.py | db/models.py | db/session.py | \
                pyproject.toml | docs/tools/v1.json | .github/workflows/ci.yml)
                shared="$f"
                ;;
        esac
    done
    if [[ -n "$shared" ]]; then
        echo "gate: $shared is shared across suites; running the full test suite"
    else
        for f in "${changed_files[@]}"; do
            case "$f" in
                tests/test_*.py)
                    [[ -f "$f" ]] && PYTEST_TARGETS+=("$f")
                    ;;
                *.py)
                    candidate="tests/test_$(basename "${f%.py}").py"
                    [[ -f "$candidate" ]] && PYTEST_TARGETS+=("$candidate")
                    ;;
            esac
        done
        if ((${#PYTEST_TARGETS[@]})); then
            mapfile -t PYTEST_TARGETS < <(printf '%s\n' "${PYTEST_TARGETS[@]}" | sort -u)
            echo "gate: pytest narrowed to ${#PYTEST_TARGETS[@]} file(s) against $CHANGED_BASE"
        else
            echo "gate: no test file maps to the diff; running the full test suite"
        fi
    fi
fi
add_step ruff-lint "uv run --no-sync ruff check ."
add_step ruff-format "uv run --no-sync ruff format --check ."
add_step mypy "uv run --no-sync mypy settings.py logging_setup.py db gateway agent scripts"
if ((${#PYLINT_TARGETS[@]})); then
    add_step pylint "uv run --no-sync pylint ${PYLINT_TARGETS[*]}"
else
    add_step pylint "echo 'pylint skipped: no Python files changed'"
fi
if ((RUN_TESTS)); then
    if ((${#PYTEST_TARGETS[@]})); then
        add_step pytest "uv run --no-sync pytest $XDIST $PYTEST_FLAGS ${PYTEST_TARGETS[*]}"
    else
        add_step pytest "uv run --no-sync pytest $XDIST $PYTEST_FLAGS"
    fi
fi
add_step adrs "uv run --no-sync python scripts/check_adrs.py"
add_step tool-catalog "uv run --no-sync python scripts/validate_tool_catalog.py --check"
add_step rbac "uv run --no-sync python scripts/validate_rbac.py"
if ((RUN_INFRA)) && command -v docker >/dev/null && [[ -f .env ]]; then
    add_step infra "docker compose config -q && docker compose -f docker-compose.yml -f docker-compose.pki.yml --profile pki config -q"
fi
add_step dread "uv run --no-sync python scripts/recalculate_dread.py --check"
add_step backlog "uv run --no-sync python scripts/check_backlog.py --check"

LAUNCH_ORDER+=(pylint mypy adrs rbac tool-catalog dread backlog infra ruff-lint ruff-format)
((RUN_TESTS)) && LAUNCH_ORDER+=(pytest)
EVALS_CMD="uv run --no-sync python scripts/run_evals.py"

start_step() {
    local name="$1" cmd="$2" log="$LOGDIR/$1.log"
    if ((VERBOSE)); then
        (
            t0=$(date +%s%N)
            bash -c "$cmd" 2>&1 | sed -u "s/^/[$name] /" | tee "$log"
            rc=${PIPESTATUS[0]}
            t1=$(date +%s%N)
            printf '%s %s %s\n' "$rc" "$t0" "$t1" >"$STATE_DIR/$name.state"
        ) &
    else
        (
            t0=$(date +%s%N)
            bash -c "$cmd" >"$log" 2>&1
            rc=$?
            t1=$(date +%s%N)
            printf '%s %s %s\n' "$rc" "$t0" "$t1" >"$STATE_DIR/$name.state"
        ) &
    fi
}

# Read the one number that makes a step's log worth reading.
detail() {
    local name="$1" log="$2" text
    case "$name" in
        ruff-lint)
            text=$(grep -oE 'All checks passed' "$log" | tail -1)
            [[ -n "$text" ]] || text=$(grep -oE 'Found [0-9]+ errors?' "$log" | tail -1)
            ;;
        ruff-format) text=$(grep -oE '[0-9]+ files? already formatted' "$log" | tail -1) ;;
        mypy) text=$(grep -oE 'no issues found in [0-9]+ source files' "$log" | tail -1) ;;
        pylint) text=$(grep -oE 'rated at [0-9.]+/10' "$log" | tail -1) ;;
        pytest)
            text=$(grep -E '(^=+ )?[0-9]+ (passed|failed)' "$log" | tail -1 |
                sed -e 's/^=*[[:space:]]*//' -e 's/[[:space:]]*in [0-9.]*s.*//')
            ;;
        evals)
            # run_evals prints one summary line before the metric table; the
            # table's last row is not the number that matters here.
            text=$(grep -oE 'evals: [0-9]+/[0-9]+ passed, [0-9]+ failed' "$log" | tail -1 |
                sed -e 's/^evals: //')
            ;;
        *) text=$(grep -vE '^[[:space:]]*$' "$log" | tail -1) ;;
    esac
    text="${text//$'\n'/ }"
    printf '%s' "${text:0:64}"
}

fmt_ms() {
    local ms="$1"
    if ((ms < 1000)); then
        printf '%dms' "$ms"
    elif ((ms < 60000)); then
        printf '%d.%ds' "$((ms / 1000))" "$(((ms % 1000) / 100))"
    else
        printf '%dm%02ds' "$((ms / 60000))" "$(((ms % 60000) / 1000))"
    fi
}

if [[ -t 1 ]]; then
    C_OK=$'\e[32m' C_BAD=$'\e[31m' C_DIM=$'\e[2m' C_OFF=$'\e[0m'
else
    C_OK= C_BAD= C_DIM= C_OFF=
fi

WALL_START=$(date +%s%N)

for name in "${LAUNCH_ORDER[@]}"; do
    while (($(jobs -rp | wc -l) >= JOBS)); do wait -n; done
    idx=-1
    for i in "${!NAMES[@]}"; do [[ "${NAMES[$i]}" == "$name" ]] && { idx=$i; break; }; done
    if ((idx < 0)); then
        # A name in LAUNCH_ORDER with no registered command would otherwise run
        # the first step's command under this name (observed while adding a step).
        echo "gate: internal error: step '$name' is in LAUNCH_ORDER but not registered" >&2
        exit 2
    fi
    start_step "$name" "${CMDS[$idx]}"
done
wait

if ((RUN_EVALS)); then
    start_step evals "$EVALS_CMD"
    wait
fi

WALL_MS=$((($(date +%s%N) - WALL_START) / 1000000))

# ---- results -----------------------------------------------------------------
FAILED=()
SERIAL_MS=0
LONGEST=0
LONGEST_NAME=""
((RUN_EVALS)) && NAMES+=(evals)

declare -A DUR RC
for name in "${NAMES[@]}"; do
    if [[ -f "$STATE_DIR/$name.state" ]]; then
        read -r rc t0 t1 <"$STATE_DIR/$name.state"
        RC[$name]="$rc"
        DUR[$name]=$(((t1 - t0) / 1000000))
    else
        # A step that never reported is a failure, not a zero-second pass.
        RC[$name]=1
        DUR[$name]=0
    fi
    [[ "${RC[$name]}" != 0 ]] && FAILED+=("$name")
    SERIAL_MS=$((SERIAL_MS + DUR[$name]))
    if ((DUR[$name] > LONGEST)); then
        LONGEST=${DUR[$name]}
        LONGEST_NAME=$name
    fi
done

WIDTH=4
for name in "${NAMES[@]}"; do ((${#name} > WIDTH)) && WIDTH=${#name}; done

printf -v RULE '%*s' "$((WIDTH + 36))" ''
RULE=${RULE// /-}

printf '\n  %-*s %-6s %8s  %s\n' "$WIDTH" "step" "status" "time" "detail"
printf '  %s\n' "$RULE"
for name in "${NAMES[@]}"; do
    # Pad first, colour second: ANSI bytes would otherwise break the column.
    if [[ "${RC[$name]}" == 0 ]]; then
        printf -v status '%s%-6s%s' "$C_OK" "ok" "$C_OFF"
    else
        printf -v status '%s%-6s%s' "$C_BAD" "FAIL" "$C_OFF"
    fi
    printf '  %-*s %s %8s  %s\n' "$WIDTH" "$name" "$status" \
        "$(fmt_ms "${DUR[$name]}")" "$(detail "$name" "$LOGDIR/$name.log")"
done

SPEEDUP=$(awk -v s="$SERIAL_MS" -v w="$WALL_MS" 'BEGIN { printf "%.2f", (w > 0 ? s / w : 1) }')
PASSED=$((${#NAMES[@]} - ${#FAILED[@]}))
VERDICT_METRICS="wall $(fmt_ms "$WALL_MS") · sum $(fmt_ms "$SERIAL_MS") · ${SPEEDUP}x · jobs $JOBS · slot $(fmt_ms "$LONGEST") ($LONGEST_NAME)"

# ---- summary.md ---------------------------------------------------------------
# One readable record per run. The per-step logs stay next to it; nothing here is
# required to steer the script, so it is safe to delete the directory wholesale.
SUMMARY="$LOGDIR/summary.md"
FAILED_LIST=$(printf '%s, ' "${FAILED[@]}")
FAILED_LIST=${FAILED_LIST%, }
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
HEAD_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
DIRTY=$(git status --porcelain 2>/dev/null | wc -l)
OUTCOME="$PASSED/${#NAMES[@]} passed"
[[ -n "$FAILED_LIST" ]] && OUTCOME="$OUTCOME — failed: $FAILED_LIST"

{
    printf '# gate · %s\n\n' "$STAMP"
    printf '| field | value |\n| --- | --- |\n'
    printf '| when | %s |\n' "$(date +%Y-%m-%dT%H:%M:%S%z)"
    printf '| branch | `%s` @ `%s` (%s dirty) |\n' "$BRANCH" "$HEAD_SHA" "$DIRTY"
    printf '| mode | tests=%s, evals=%s, jobs=%s |\n' "$TEST_MODE" \
        "$([[ $RUN_EVALS == 1 ]] && echo on || echo off)" "$JOBS"
    printf '| result | %s |\n' "$OUTCOME"
    printf '| wall / sum | %s / %s (%sx) |\n' "$(fmt_ms "$WALL_MS")" "$(fmt_ms "$SERIAL_MS")" "$SPEEDUP"
    printf '| slowest step | %s (%s) |\n' "$LONGEST_NAME" "$(fmt_ms "$LONGEST")"
    printf '\n## Steps\n\n| step | status | time | detail |\n| --- | --- | --- | --- |\n'
    for name in "${NAMES[@]}"; do
        if [[ "${RC[$name]}" == 0 ]]; then step_status=ok; else step_status=FAIL; fi
        step_detail=$(detail "$name" "$LOGDIR/$name.log")
        printf '| `%s` | %s | %s | %s |\n' "$name" "$step_status" \
            "$(fmt_ms "${DUR[$name]}")" "${step_detail//|/\\|}"
    done
    if ((${#FAILED[@]})); then
        printf '\n## Failures\n'
        for name in "${FAILED[@]}"; do
            printf '\n### %s\n\n```text\n' "$name"
            tail -n 20 "$LOGDIR/$name.log"
            printf '```\n'
        done
    fi
} >"$SUMMARY"
ln -sfn "$STAMP" artifacts/gate/latest

if ((${#FAILED[@]} == 0)); then
    printf '\ngate: %d/%d passed · %s\n' "$PASSED" "${#NAMES[@]}" "$VERDICT_METRICS"
    printf 'summary: %s\n' "$SUMMARY"
    exit 0
fi

printf '\ngate: %d/%d passed · FAILED: %s · %s\n' "$PASSED" "${#NAMES[@]}" \
    "$FAILED_LIST" "$VERDICT_METRICS" >&2

for name in "${FAILED[@]}"; do
    printf '\n--- %s (last 30 lines) ---\n' "$name" >&2
    tail -n 30 "$LOGDIR/$name.log" >&2
done
printf '\nsummary + logs: %s\n' "$LOGDIR" >&2
exit 1
