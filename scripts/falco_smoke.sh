#!/usr/bin/env bash
# Prove the Falco rules against the running stack.
#
# Requires a Linux host whose kernel exposes syscall tracepoints or fentry to a
# privileged container (ADR-017). The Docker Desktop path works for the shell,
# write and egress rules but cannot resolve /proc metadata such as proc.cmdline,
# so the data-container healthcheck exception is ineffective there; this script
# reports that as a warning rather than a hard failure.
#
#   scripts/falco_smoke.sh
#
# Exit codes: 0 every required rule fired and the negative cases stayed silent,
# 1 a required rule did not fire or a negative case alerted, 2 setup error.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

EVENTS="artifacts/falco/events.json"
WAIT_SECONDS="${FALCO_WAIT_SECONDS:-12}"

command -v docker >/dev/null || { echo "falco-smoke: docker is not on PATH" >&2; exit 2; }

docker compose ps gateway worker db redis >/dev/null 2>&1 || {
    echo "falco-smoke: the default stack must be running" >&2
    exit 2
}

docker compose --profile security up -d falco >/dev/null 2>&1 || {
    echo "falco-smoke: cannot start the falco profile" >&2
    exit 2
}

for _ in $(seq 1 "$WAIT_SECONDS"); do
    if docker compose logs falco 2>&1 | grep -q "Opening 'syscall' source"; then
        break
    fi
    sleep 2
done
if ! docker compose logs falco 2>&1 | grep -q "Opening 'syscall' source"; then
    echo "falco-smoke: Falco did not open the syscall source" >&2
    exit 2
fi

mkdir -p artifacts/falco
: > "$EVENTS"

fail=0
expect_rule() {
    local rule="$1"
    if grep -q "\"rule\":\"$rule\"" "$EVENTS"; then
        echo "ok: $rule"
    else
        echo "MISSING: $rule" >&2
        fail=1
    fi
}

echo "falco-smoke: triggering the required rules"
docker exec bastion-agent-gateway-1 sh -c 'id' >/dev/null 2>&1
sleep 2
expect_rule "Bastion shell spawned in an application container"

docker exec bastion-agent-worker-1 python -c \
    "open('/home/bastion/falco-smoke','w').write('x')" >/dev/null 2>&1
sleep 2
expect_rule "Bastion worker write outside the tool workspace"

docker exec bastion-agent-gateway-1 python -c \
    "import socket; socket.create_connection(('1.1.1.1',443),3)" >/dev/null 2>&1
sleep 2
expect_rule "Bastion gateway egress outside the allowlist"

echo "falco-smoke: negative cases"
before=$(wc -l < "$EVENTS")
docker exec bastion-agent-worker-1 python -c \
    "import os; os.makedirs('/tmp/bastion-workspace', exist_ok=True); open('/tmp/bastion-workspace/falco-smoke','w').write('x')" \
    >/dev/null 2>&1
docker exec bastion-agent-gateway-1 python -c \
    "import socket; socket.create_connection(('db',5432),3)" >/dev/null 2>&1
sleep 2
after=$(wc -l < "$EVENTS")
if [ "$after" -eq "$before" ]; then
    echo "ok: workspace write and allowlisted egress stayed silent"
else
    echo "UNEXPECTED: the negative cases produced alerts" >&2
    fail=1
fi

echo "falco-smoke: alert payload check"
for pattern in VAULT_MASTER_KEY OPENROUTER_API_KEY DATABASE_URL REDIS_PASSWORD; do
    value="$(grep -E "^${pattern}=" .env 2>/dev/null | cut -d= -f2- || true)"
    if [ -n "$value" ] && grep -qF "$value" "$EVENTS"; then
        echo "LEAK: $pattern appears in the alert file" >&2
        fail=1
    fi
done
if grep -qE '"(proc\.cmdline|proc\.args|proc\.env|evt\.buffer)"' "$EVENTS"; then
    echo "LEAK: an alert carries process arguments or environment" >&2
    fail=1
fi
[ "$fail" -eq 0 ] && echo "falco-smoke: ok ($(wc -l < "$EVENTS") alert(s) in $EVENTS)"
exit "$fail"
