#!/bin/sh
# Runs inside the pinned Trivy image (compliance profile).
#
# /images holds one `docker save` tarball per image, written by
# scripts/scan_images.sh. Each scan writes a CycloneDX SBOM and a Trivy JSON
# report to /reports. No Docker socket, no registry credentials, no privileges:
# the scanner only reads tar files.
#
# Exit 0 when every tarball was scanned, 2 when there is nothing to scan (so a
# misconfigured run cannot look green), 1 when a Trivy invocation failed.

set -eu

images_dir="${IMAGES_DIR:-/images}"
reports_dir="${REPORTS_DIR:-/reports}"
export TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/cache}"
export TRIVY_NO_PROGRESS="${TRIVY_NO_PROGRESS:-true}"

mkdir -p "$reports_dir"

count=0
for tarball in "$images_dir"/*.tar; do
    [ -f "$tarball" ] || continue
    name="$(basename "$tarball" .tar)"
    count=$((count + 1))
    echo "trivy-scan: $name"

    # Trivy cannot emit CycloneDX and JSON from one invocation, so the two
    # analyses run concurrently: they read the same read-only tarball and share
    # nothing, which roughly halves the per-image wall time on a multi-core
    # runner. A failure in either format fails the image.
    trivy image \
        --input "$tarball" \
        --scanners vuln \
        --format cyclonedx \
        --output "$reports_dir/$name.cdx.json" \
        --quiet &
    cdx_pid=$!

    trivy image \
        --input "$tarball" \
        --scanners vuln \
        --format json \
        --output "$reports_dir/$name.json" \
        --quiet &
    json_pid=$!

    rc=0
    wait "$cdx_pid" || rc=1
    wait "$json_pid" || rc=1
    if [ "$rc" -ne 0 ]; then
        echo "trivy-scan: a format failed for $name" >&2
        exit 1
    fi
done

if [ "$count" -eq 0 ]; then
    echo "trivy-scan: no image tarballs in $images_dir" >&2
    echo "trivy-scan: run scripts/scan_images.sh, which saves them first" >&2
    exit 2
fi

echo "trivy-scan: scanned $count image(s)"
