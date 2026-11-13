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
# than CPU- or disk-bound, so they run concurrently with the local image build.
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
    build=0
    for image in "${missing[@]}"; do
        if [[ "$image" == bastion-agent:* ]]; then
            build=1
        else
            registry+=("$image")
        fi
    done
    build_pid=""
    if [ "$build" -eq 1 ]; then
        (
            start=$SECONDS
            echo "scan-images: building gateway"
            docker compose build gateway || exit 1
            echo "scan-images: gateway build took $((SECONDS - start))s"
        ) &
        build_pid=$!
    fi
    pull_failed=0
    if ((${#registry[@]})); then
        start=$SECONDS
        echo "scan-images: pulling ${#registry[@]} image(s) with ${JOBS} workers"
        printf '%s\n' "${registry[@]}" |
            xargs -r -P "$JOBS" -I{} sh -c 'echo "scan-images: pull $1"; docker pull "$1"' _ {} || pull_failed=1
        echo "scan-images: pulls took $((SECONDS - start))s"
        pulled+=("${registry[@]}")
    fi
    build_failed=0
    if [ -n "$build_pid" ]; then
        wait "$build_pid" || build_failed=1
    fi
    if [ "$build_failed" -eq 1 ] || [ "$pull_failed" -eq 1 ]; then
        echo "scan-images: image build or pull failed" >&2
        exit 2
    fi
fi

for image in "${IMAGES[@]}"; do
    slug="$(uv run python scripts/image_inventory.py --slug "$image")"
    start=$SECONDS
    echo "scan-images: export $slug"
    docker save "$image" -o "$WORK/images/$slug.tar"
    echo "scan-images: export $slug took $((SECONDS - start))s"
    # `docker save` honours a restrictive umask; the scanner runs as root in a
    # container with cap_drop: ALL and only needs read access to the archive.
    chmod 0644 "$WORK/images/$slug.tar"

    echo "scan-images: scan $slug"
    start=$SECONDS
    docker compose --profile compliance run --rm --no-deps trivy-scan
    echo "scan-images: scan $slug took $((SECONDS - start))s"

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
