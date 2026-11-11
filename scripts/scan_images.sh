#!/usr/bin/env bash
# Scan every image the compose stack ships and gate on CRITICAL CVEs.
#
# The scanner never gets the Docker socket. Images are exported with
# `docker save` into a staging directory, then the pinned Trivy container reads
# those tarballs from a read-only mount. That keeps the `cap_drop: ALL` baseline
# true and means the SBOM describes the bytes that are actually shipped.
#
#   scripts/scan_images.sh                    # scan images already on the host
#   scripts/scan_images.sh --build-missing    # build/pull what is absent first
#   scripts/scan_images.sh --keep-work        # keep tarballs (debugging)
#   scripts/scan_images.sh --compose FILE     # inventory from another compose file
#
# Images are scanned one archive at a time so peak disk stays bounded.
#
# Artifacts: artifacts/compliance/<UTC date>/{sbom.cdx.json,cve.json,manifest.json}
# Exit codes: 0 clean, 1 unsuppressed CRITICAL or policy violation, 2 setup error.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

BUILD_MISSING=0
KEEP_WORK=0
COMPOSE_FILE="docker-compose.yml"
while (($#)); do
    case "$1" in
        --build-missing) BUILD_MISSING=1 ;;
        --keep-work) KEEP_WORK=1 ;;
        --compose)
            [[ $# -ge 2 ]] || { echo "scan-images: --compose needs a file" >&2; exit 2; }
            COMPOSE_FILE="$2"
            shift
            ;;
        -h | --help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
        *) echo "scan-images: unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

command -v docker >/dev/null || { echo "scan-images: docker is not on PATH" >&2; exit 2; }
command -v uv >/dev/null || { echo "scan-images: uv is not on PATH" >&2; exit 2; }

# Rendering compose needs every ${VAR:?} value, including secrets the scan never
# uses. Supply throwaway values for the unset ones; never overwrite a real value.
while IFS= read -r name; do
    if [ -z "${!name:-}" ]; then
        export "$name=compliance-scan-render-only"
    fi
done < <(uv run python scripts/image_inventory.py --required-vars)

mapfile -t IMAGES < <(uv run python scripts/image_inventory.py --compose "$COMPOSE_FILE")
if [ "${#IMAGES[@]}" -eq 0 ]; then
    echo "scan-images: no images found in docker-compose.yml" >&2
    exit 2
fi

WORK="artifacts/compliance/work"
OUT="artifacts/compliance/$(date -u +%F)"
rm -rf "$WORK"
mkdir -p "$WORK/images" "$WORK/raw" "$OUT"
# The scanner is root inside a cap_drop: ALL container, so it has no
# DAC_OVERRIDE: mounted directories it must write must be world-writable.
# The directory is a scratch path under artifacts/ and is removed afterwards.
chmod 0777 "$WORK/raw"

echo "scan-images: ${#IMAGES[@]} image reference(s)"
pulled=()
for image in "${IMAGES[@]}"; do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        if [ "$BUILD_MISSING" -eq 1 ] && [[ "$image" == bastion-agent:* ]]; then
            echo "scan-images: building $image"
            docker compose build gateway
        elif [ "$BUILD_MISSING" -eq 1 ]; then
            echo "scan-images: pulling $image"
            docker pull "$image"
            pulled+=("$image")
        else
            echo "scan-images: image not present: $image" >&2
            echo "scan-images: run with --build-missing (or docker pull/build it first)" >&2
            exit 2
        fi
    fi
    slug="$(uv run python scripts/image_inventory.py --slug "$image")"
    echo "scan-images: export $slug"
    docker save "$image" -o "$WORK/images/$slug.tar"
    # `docker save` honours a restrictive umask; the scanner runs as root in a
    # container with cap_drop: ALL and only needs read access to the archive.
    chmod 0644 "$WORK/images/$slug.tar"

    echo "scan-images: scan $slug"
    docker compose --profile compliance run --rm --no-deps trivy-scan

    # One tarball at a time keeps peak disk bounded: the CUDA image alone is a
    # multi-gigabyte archive and a hosted runner does not have room for nine.
    rm -f "$WORK/images/$slug.tar"
    if printf '%s\n' "${pulled[@]:-}" | grep -qxF "$image"; then
        docker rmi "$image" >/dev/null 2>&1 || true
    fi
done

echo "scan-images: aggregating reports"
uv run python scripts/aggregate_trivy_reports.py \
    --raw "$WORK/raw" --out "$OUT" "${IMAGES[@]}"

echo "scan-images: gate"
set +e
uv run python scripts/check_trivy_report.py --report "$OUT/cve.json" --policy trivy.yaml
status=$?
set -e

if [ "$KEEP_WORK" -eq 0 ]; then
    rm -rf "$WORK"
fi

echo "scan-images: artifacts in $OUT (exit $status)"
exit "$status"
