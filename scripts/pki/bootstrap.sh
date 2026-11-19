#!/usr/bin/env bash
# Create the pki profile's host-side material before the stack starts (ADR-019).
#
#   ./scripts/pki/bootstrap.sh
#
# Idempotent: existing password files are never rewritten, so re-running it
# cannot lock the CA out of its own encryption password.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

mkdir -p secrets
mkdir -p pki/trust pki/db pki/redis pki/keycloak pki/gateway pki/worker pki/migrate
chmod 700 secrets

generate() {
    local path=$1
    if [[ -s "$path" ]]; then
        chmod 600 "$path"
        echo "keep  $path"
        return
    fi
    python3 -c 'import secrets; print(secrets.token_urlsafe(32))' >"$path"
    chmod 600 "$path"
    echo "write $path"
}

generate secrets/ca_password
generate secrets/provisioner_password

if [[ ! -f pki/ca/config/ca.json ]]; then
    echo "next  docker compose -f docker-compose.yml -f docker-compose.pki.yml --profile pki up -d"
else
    echo "keep  pki/ca/config/ca.json (existing CA left untouched)"
fi
