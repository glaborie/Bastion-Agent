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
#   scripts/scan_images.sh --jobs 8           # concurrent registry pulls (default 4)
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
JOBS="${SCAN_JOBS:-4}"
while (($#)); do
    case "$1" in
        --build-missing) BUILD_MISSING=1 ;;
        --keep-work) KEEP_WORK=1 ;;
        --jobs)
            [[ $# -ge 2 ]] || { echo "scan-images: --jobs needs a number" >&2; exit 2; }
            JOBS="$2"
            shift
            ;;
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

[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "scan-images: --jobs must be a positive integer" >&2; exit 2; }

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

# Fetch phase. Pulling eight registry images one after another is the single
# slowest part of a CI run on a fresh runner, and a pull is network-bound rather
# than CPU- or disk-bound, so they run concurrently. The local image is built
# once and serialised because `docker compose build` already parallelises its
# own stages.
pulled=()
missing=()
for image in "${IMAGES[@]}"; do
    docker image inspect "$image" >/dev/null 2>&1 || missing+=("$image")
done

if ((${#missing[@]})); then
    if [ "$BUILD_MISSING" -ne 1 ]; then
        for image in "${missing[@]}"; do
            echo "scan-images: image not present: $image" >&2
        done
        echo "scan-images: run with --build-missing (or docker pull/build it first)" >&2
        exit 2
    fi
    registry=()
    for image in "${missing[@]}"; do
        if [[ "$image" == bastion-agent:* ]]; then
            echo "scan-images: building $image"
            docker compose build gateway
        else
            registry+=("$image")
        fi
    done
    if ((${#registry[@]})); then
        echo "scan-images: pulling ${#registry[@]} image(s) with ${JOBS} workers"
        printf '%s\n' "${registry[@]}" |
            xargs -r -P "$JOBS" -I{} sh -c 'echo "scan-images: pull $1"; docker pull "$1"' _ {}
        pulled+=("${registry[@]}")
    fi
fi

for image in "${IMAGES[@]}"; do
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
