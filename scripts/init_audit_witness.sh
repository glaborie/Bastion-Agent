#!/usr/bin/env bash
# Create the audit-witness bucket and its append-only credential (ADR-005
# decision 9). Runs once per `--profile compliance up` and is idempotent, so a
# restart or a second `up` neither fails nor reopens the retention window.
#
# The application credential may append under the witness prefix and read it
# back. It may not delete a version, shorten the bucket's retention, turn
# versioning off or change the bucket policy: those are server-side refusals, not
# client discipline.
set -euo pipefail

MC="${MC_BIN:-mc}"
POLICY="${AUDIT_WITNESS_POLICY:-/opt/bastion/audit-witness-policy.json}"
: "${MINIO_ENDPOINT:?MINIO_ENDPOINT is required}"
: "${MINIO_ROOT_USER:?MINIO_ROOT_USER is required}"
: "${MINIO_ROOT_PASSWORD:?MINIO_ROOT_PASSWORD is required}"
: "${AUDIT_WITNESS_BUCKET:?AUDIT_WITNESS_BUCKET is required}"
: "${AUDIT_WITNESS_ACCESS_KEY:?AUDIT_WITNESS_ACCESS_KEY is required}"
: "${AUDIT_WITNESS_SECRET_KEY:?AUDIT_WITNESS_SECRET_KEY is required}"
RETENTION_YEARS="${AUDIT_WITNESS_RETENTION_YEARS:-7}"

export MC_CONFIG_DIR="${MC_CONFIG_DIR:-/tmp/mc}"
mkdir -p "$MC_CONFIG_DIR"

"$MC" alias set bastion "$MINIO_ENDPOINT" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null

# --with-lock creates the bucket with object locking; --with-versioning is
# required by every object-lock bucket. Both flags are inert on an existing
# bucket, so the command stays idempotent.
"$MC" mb --ignore-existing --with-lock --with-versioning "bastion/$AUDIT_WITNESS_BUCKET" >/dev/null
"$MC" version enable "bastion/$AUDIT_WITNESS_BUCKET" >/dev/null
"$MC" retention set --default compliance "${RETENTION_YEARS}y" "bastion/$AUDIT_WITNESS_BUCKET" >/dev/null

# Re-running the init must not reset an existing credential, so create it only
# when absent. The policy is declarative config, though: it is re-applied on
# every run so a new statement (the ledger export prefix, ADR-005 decision 10)
# reaches an existing bucket without an operator remembering to do it.
if ! "$MC" admin user info bastion "$AUDIT_WITNESS_ACCESS_KEY" >/dev/null 2>&1; then
    "$MC" admin user add bastion "$AUDIT_WITNESS_ACCESS_KEY" "$AUDIT_WITNESS_SECRET_KEY" >/dev/null
fi
"$MC" admin policy create bastion audit-witness "$POLICY" >/dev/null
"$MC" admin policy attach bastion audit-witness --user "$AUDIT_WITNESS_ACCESS_KEY" 2>/dev/null ||
    echo "minio-init: witness policy already attached"

echo "minio-init: bucket $AUDIT_WITNESS_BUCKET"
"$MC" retention info "bastion/$AUDIT_WITNESS_BUCKET"
"$MC" version info "bastion/$AUDIT_WITNESS_BUCKET"
