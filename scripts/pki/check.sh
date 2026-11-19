#!/usr/bin/env bash
# Assert the pki material on this tree is what ADR-019 describes.
#
#   ./scripts/pki/check.sh
#
# Green on a tree that has only run scripts/pki/bootstrap.sh; once init-ca and
# issue-certs have run it also checks the CA key's mode and every leaf's subject,
# SANs, validity and issuer. Exit 0 clean, 1 on any failed assertion.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Same pin as docker-compose.pki.yml: the CA key's mode is readable only as root.
PKI_IMAGE="smallstep/step-ca:0.28.4@sha256:0f88382ac5af5c6b7bbba0c6e8fcefef52aee6f22ea364df8e02a09ffd0d22f3"
fail=0
err() {
    echo "pki-check: $*" >&2
    fail=1
}

mode_of() {
    stat -c %a "$1"
}

# Compose secret files: owner-only and never trackable.
if [[ ! -d secrets ]]; then
    err "secrets/ is missing; run scripts/pki/bootstrap.sh"
else
    [[ "$(mode_of secrets)" == 700 ]] || err "secrets/ is mode $(mode_of secrets), expected 700"
fi
for file in secrets/ca_password secrets/provisioner_password; do
    if [[ ! -f "$file" ]]; then
        err "$file is missing; run scripts/pki/bootstrap.sh"
        continue
    fi
    [[ "$(mode_of "$file")" == 600 ]] || err "$file is mode $(mode_of "$file"), expected 600"
    if git ls-files --error-unmatch "$file" >/dev/null 2>&1; then
        err "$file is tracked"
    fi
    git check-ignore -q "$file" || err "$file is not gitignored"
done

# The root and intermediate keys live in a directory only the CA mounts.
if [[ -d pki/ca ]]; then
    if git ls-files --error-unmatch pki/ca/secrets/root_ca_key >/dev/null 2>&1; then
        err "pki/ca/secrets/root_ca_key is tracked"
    fi
    git check-ignore -q pki/ca/secrets/root_ca_key || err "pki/ca/secrets/root_ca_key is not gitignored"
    docker run --rm -v "$ROOT/pki:/pki:ro" --entrypoint sh "$PKI_IMAGE" -c '
        set -e
        [ -f /pki/ca/config/ca.json ]
        [ "$(stat -c %a /pki/ca)" = 700 ]
        [ "$(stat -c %a /pki/ca/secrets)" = 700 ]
        for key in root_ca_key intermediate_ca_key; do
            [ "$(stat -c %a "/pki/ca/secrets/$key")" = 600 ]
        done
    ' || err "CA key material under pki/ca is not owner-only (0600 in a 0700 directory)"
fi

# Leaves: subject, SANs, validity and that the CA signed them. The public trust
# bundle is readable, so this half needs no root.
if [[ -f pki/trust/ca.crt ]] && compgen -G "pki/*/tls.crt" >/dev/null; then
    if ! uv run --no-sync python - <<'PY'
import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID

# service -> (common name, required DNS SANs, required IP SANs)
EXPECTED = {
    "db": ("db", {"db", "localhost"}, {"127.0.0.1"}),
    "redis": ("redis", {"redis"}, set()),
    "keycloak": ("keycloak", {"keycloak"}, set()),
    "gateway": ("bastion_app", set(), set()),
    "worker": ("bastion_app", set(), set()),
    "migrate": ("bastion", set(), set()),
}

chain = x509.load_pem_x509_certificates(Path("pki/trust/ca.crt").read_bytes())
roots = [c for c in chain if c.issuer == c.subject]
intermediates = [c for c in chain if c.issuer != c.subject]
if len(roots) != 1 or len(intermediates) != 1:
    sys.exit("pki/trust/ca.crt must hold exactly one root and one intermediate")
root, intermediate = roots[0], intermediates[0]

now = dt.datetime.now(dt.timezone.utc)
errors: list[str] = []
for service, (cn, dns, ips) in EXPECTED.items():
    crt_path = Path(f"pki/{service}/tls.crt")
    if not crt_path.is_file():
        errors.append(f"{service}: missing {crt_path}")
        continue
    leaf = x509.load_pem_x509_certificate(crt_path.read_bytes())
    if not isinstance(leaf.public_key(), (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)):
        errors.append(f"{service}: unsupported public key")
    try:
        leaf.verify_directly_issued_by(intermediate)
        intermediate.verify_directly_issued_by(root)
    except Exception as exc:  # noqa: BLE001 - the message is the assertion
        errors.append(f"{service}: not signed by the tree CA ({exc})")
    names = [a.value for a in leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
    if names != [cn]:
        errors.append(f"{service}: common name {names}, expected {cn}")
    if leaf.not_valid_before_utc > now or leaf.not_valid_after_utc < now:
        errors.append(f"{service}: outside its validity window")
    if leaf.not_valid_after_utc - leaf.not_valid_before_utc > dt.timedelta(days=30):
        errors.append(f"{service}: lifetime exceeds 30 days")
    try:
        san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        san = x509.SubjectAlternativeName([])
    got_dns = set(san.get_values_for_type(x509.DNSName))
    got_ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    if not dns <= got_dns:
        errors.append(f"{service}: DNS SANs {sorted(got_dns)}, expected {sorted(dns)}")
    if not ips <= got_ips:
        errors.append(f"{service}: IP SANs {sorted(got_ips)}, expected {sorted(ips)}")

for message in errors:
    print(f"pki-check: {message}", file=sys.stderr)
sys.exit(1 if errors else 0)
PY
    then
        fail=1
    fi
fi

if ((fail)); then
    exit 1
fi
echo "pki-check: ok"
