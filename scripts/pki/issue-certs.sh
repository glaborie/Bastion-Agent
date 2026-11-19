#!/bin/sh
# Issue one leaf per service from a locally generated CSR (ADR-019 decision 3).
#
#   pki-issue (compose), or by hand inside the CA network:
#   PKI_CA_URL=https://ca:9000 ... /scripts/issue-certs.sh
#
# The private key never leaves this run: the CA signs a CSR, and the key is
# written straight into the service's directory with mode 0600.
set -eu

CA_URL="${PKI_CA_URL:-https://ca:9000}"
CA_ROOT="${PKI_CA_ROOT:-/pki/ca/certs/root_ca.crt}"
PROVISIONER="${PKI_PROVISIONER:-bastion-admin}"
PROVISIONER_PASSWORD="${PKI_PROVISIONER_PASSWORD_FILE:-/run/secrets/provisioner_password}"
CERT_TTL="${PKI_CERT_TTL:-24h}"
DB_ROLE="${POSTGRES_USER:-bastion}"
APP_ROLE="${POSTGRES_APP_USER:-bastion_app}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

issue() {
    service=$1
    common_name=$2
    owner=$3
    shift 3

    step certificate create "$common_name" "$workdir/$service.csr" "$workdir/$service.key" \
        --csr --kty EC --crv P-256 --no-password --insecure "$@"
    step ca sign \
        --ca-url "$CA_URL" \
        --root "$CA_ROOT" \
        --provisioner "$PROVISIONER" \
        --provisioner-password-file "$PROVISIONER_PASSWORD" \
        --not-after "$CERT_TTL" \
        "$workdir/$service.csr" "$workdir/$service.crt"

    install -d -m 755 "/pki/$service"
    install -m 644 "$workdir/$service.crt" "/pki/$service/tls.crt"
    install -m 600 "$workdir/$service.key" "/pki/$service/tls.key"
    chown -R "$owner" "/pki/$service"
    echo "pki-issue: issued $service ($common_name) for uid ${owner%%:*}"
}

# Server leaves carry the DNS names a client verifies. The database also
# answers on loopback for the host-side probes in docs/PKI.md.
issue db db 70:70 --san db --san localhost --san 127.0.0.1
issue redis redis 999:1000 --san redis
issue keycloak keycloak 1000:0 --san keycloak
# Client leaves: PostgreSQL's `cert` method maps the CN to the database role.
issue gateway "$APP_ROLE" 10001:10001
issue worker "$APP_ROLE" 10001:10001
issue migrate "$DB_ROLE" 10001:10001
