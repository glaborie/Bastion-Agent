#!/bin/sh
# One-shot CA initialisation inside the pki-init container (ADR-019 decision 2).
#
# An existing ca.json is left untouched: regenerating the root would orphan
# every leaf already issued from it.
set -eu

if [ ! -f /pki/ca/config/ca.json ]; then
    STEPPATH=/pki/ca
    export STEPPATH

    set -- \
        --deployment-type standalone \
        --name "${PKI_CA_NAME:-Bastion Internal CA}" \
        --address "${PKI_CA_ADDRESS:-:9000}" \
        --provisioner "${PKI_PROVISIONER:-bastion-admin}" \
        --password-file /run/secrets/ca_password \
        --provisioner-password-file /run/secrets/provisioner_password
    for dns in $(printf '%s' "${PKI_CA_DNS:-ca}" | tr ',' ' '); do
        set -- "$@" --dns "$dns"
    done

    step ca init "$@"
else
    echo "pki-init: /pki/ca/config/ca.json exists; leaving the CA untouched"
fi

# The CA key lives in a directory only the CA container mounts.
chmod 700 /pki/ca /pki/ca/secrets
chmod 600 /pki/ca/secrets/root_ca_key /pki/ca/secrets/intermediate_ca_key

# Clients and servers trust the intermediate as well as the root: step-ca
# signs leaves with an intermediate, and PostgreSQL, Redis and Python all load
# a PEM bundle from one path.
cat /pki/ca/certs/root_ca.crt /pki/ca/certs/intermediate_ca.crt >/pki/trust/ca.crt
chmod 644 /pki/trust/ca.crt
