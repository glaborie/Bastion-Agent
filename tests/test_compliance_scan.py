"""Compliance scanning: image inventory, report aggregation and the CVE gate.

The Trivy container itself is exercised by ``scripts/scan_images.sh`` against a
real daemon; these tests pin the pure pieces that decide coverage and pass/fail,
so a regression fails without needing Docker or network access.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "docker-compose.yml"

# The eleven shipped image references: IDEA-019's nine, the audit-witness store
# (IDEA-021) and the availability monitor (IDEA-039).
EXPECTED_IMAGES = {
    "bastion-agent:local",
}
EXPECTED_IMAGE_PREFIXES = (
    "postgres:16.15-alpine@sha256:",
    "dpage/pgadmin4:9.19@sha256:",
    "redis:7-alpine@sha256:",
    "redis/redisinsight:3.8@sha256:",
    "quay.io/keycloak/keycloak:26.8.2@sha256:",
    "ghcr.io/ggml-org/llama.cpp:server-cuda@sha256:",
    "otel/opentelemetry-collector-contrib:0.165.0@sha256:",
    "diegosouzapw/omniroute:3.8.53@sha256:",
    "cgr.dev/chainguard/minio:latest@sha256:",
    "louislam/uptime-kuma:2.5.12@sha256:",
)


def run_script(
    script: str, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    merged = dict(os.environ)
    if env is not None:
        merged.update(env)
    return subprocess.run(
        [sys.executable, str(ROOT / script), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=merged,
    )


@pytest.mark.parametrize("failure", ["", "build", "pull"])
def test_scan_overlaps_build_and_pulls_and_fails_closed(tmp_path: Path, failure: str) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    scan = scripts / "scan_images.sh"
    scan.write_text((ROOT / "scripts/scan_images.sh").read_text(encoding="utf-8"), encoding="utf-8")
    scan.chmod(0o755)
    binary = tmp_path / "bin"
    binary.mkdir()
    uv = binary / "uv"
    uv.write_text(
        """#!/bin/sh
case "$*" in
    *--required-vars*) ;;
    *--compose*) printf '%s\\n' bastion-agent:local registry/image:tag ;;
    *--slug*) printf '%s\\n' "${5//\\//-}" ;;
esac
""".replace("#!/bin/sh", "#!/bin/bash"),
        encoding="utf-8",
    )
    docker = binary / "docker"
    docker.write_text(
        """#!/bin/sh
case "$*" in
    "image inspect "*) exit 1 ;;
    "compose build gateway")
        touch "$FAKE_STATE/build"
        [ "$FAIL_STAGE" != build ] || exit 1
        n=0
        while [ ! -e "$FAKE_STATE/pull" ]; do
            n=$((n + 1)); [ "$n" -lt 100 ] || exit 1; sleep 0.05
        done ;;
    "pull "*)
        touch "$FAKE_STATE/pull"
        [ "$FAIL_STAGE" != pull ] || exit 1
        n=0
        while [ ! -e "$FAKE_STATE/build" ]; do
            n=$((n + 1)); [ "$n" -lt 100 ] || exit 1; sleep 0.05
        done ;;
    "save "*)
        for last do :; done
        touch "$last" ;;
    "compose --profile"*) touch "$FAKE_STATE/scan" ;;
esac
""",
        encoding="utf-8",
    )
    for path in (uv, docker):
        path.chmod(0o755)
    result = subprocess.run(
        [str(scan), "--build-missing"],
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": f"{binary}:{os.environ['PATH']}",
            "FAKE_STATE": str(tmp_path),
            "FAIL_STAGE": failure,
        },
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    assert (tmp_path / "build").exists()
    assert (tmp_path / "pull").exists()
    if failure:
        assert result.returncode == 2, result.stderr
        assert not (tmp_path / "scan").exists()
    else:
        assert result.returncode == 0, result.stderr
        assert (tmp_path / "scan").exists()


def write_policy(tmp_path: Path, entries: list[dict[str, Any]]) -> Path:
    path = tmp_path / "trivy.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "ignore": entries}), encoding="utf-8")
    return path


def ignore_entry(
    vulnerability_id: str = "CVE-2024-0001",
    images: list[str] | None = None,
    statement: str = "No fixed release; accepted until the next base image bump.",
    expires: str = "2027-01-31",
) -> dict[str, Any]:
    return {
        "id": vulnerability_id,
        "images": images or ["alpine-3.20"],
        "statement": statement,
        "expires": expires,
    }


def write_report(tmp_path: Path, image: str, vulnerability_ids: list[str]) -> Path:
    report = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "alpine:3.20 (alpine 3.20.0)",
                "BastionImage": image,
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": vulnerability_id,
                        "PkgName": "openssl",
                        "InstalledVersion": "3.3.0-r0",
                        "FixedVersion": "",
                        "Severity": "CRITICAL",
                    }
                    for vulnerability_id in vulnerability_ids
                ],
            }
        ],
    }
    path = tmp_path / "cve.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def test_default_compose_inventory_is_the_shipped_set() -> None:
    # --no-env-file: the assertion is about the file's defaults, not a dev .env.
    # The empty overrides neutralise image variables that a loaded .env may have
    # exported into this process; Compose treats an empty value as unset.
    result = run_script(
        "scripts/image_inventory.py",
        "--no-env-file",
        env={"LLAMA_CPP_IMAGE": "", "OMNIROUTE_IMAGE": "", "BASTION_IMAGE_TAG": ""},
    )
    assert result.returncode == 0, result.stderr
    images = result.stdout.splitlines()
    assert len(images) == 11
    assert set(images) >= EXPECTED_IMAGES
    for prefix in EXPECTED_IMAGE_PREFIXES:
        assert any(image.startswith(prefix) for image in images), prefix
    assert not any("aquasecurity/trivy" in image for image in images)


def test_inventory_grows_with_a_new_image_line(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  a:\n    image: alpine:3.20\n  b:\n    image: ${B_IMAGE:-busybox:1.36}\n",
        encoding="utf-8",
    )
    before = run_script("scripts/image_inventory.py", "--compose", str(compose), "--no-env-file")
    assert before.returncode == 0, before.stderr
    assert before.stdout.splitlines() == ["alpine:3.20", "busybox:1.36"]

    compose.write_text(
        compose.read_text(encoding="utf-8") + "  c:\n    image: redis:7-alpine\n",
        encoding="utf-8",
    )
    after = run_script("scripts/image_inventory.py", "--compose", str(compose), "--no-env-file")
    assert after.returncode == 0, after.stderr
    assert after.stdout.splitlines() == ["alpine:3.20", "busybox:1.36", "redis:7-alpine"]


def test_inventory_excludes_the_scanner_and_detector_but_keeps_services(
    tmp_path: Path,
) -> None:
    # A profile alone no longer means "tooling": the MinIO witness store runs
    # behind `compliance` and is a service the stack serves from, so it must be
    # scanned. Only the Trivy scanner and Falco are controls around the stack.
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  shipped:\n"
        "    image: alpine:3.20\n"
        "  trivy-scan:\n"
        "    image: ghcr.io/aquasecurity/trivy:0.76.1\n"
        "    profiles: [compliance]\n"
        "  falco:\n"
        "    image: falcosecurity/falco:0.45.2\n"
        "    profiles: [security]\n"
        "  minio:\n"
        "    image: cgr.dev/chainguard/minio:latest\n"
        "    profiles: [compliance]\n",
        encoding="utf-8",
    )
    result = run_script("scripts/image_inventory.py", "--compose", str(compose), "--no-env-file")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "alpine:3.20",
        "cgr.dev/chainguard/minio:latest",
    ]


def test_inventory_rejects_an_unset_required_variable(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  a:\n    image: ${MISSING:?set it}\n", encoding="utf-8")
    result = run_script("scripts/image_inventory.py", "--compose", str(compose), "--no-env-file")
    assert result.returncode == 2
    assert "MISSING" in result.stderr


def test_env_file_supplies_overrides_and_process_env_wins(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  a:\n    image: ${PROBE_IMAGE:-alpine:3.20}\n", encoding="utf-8"
    )
    env_file = tmp_path / ".env"
    env_file.write_text("# local override\nPROBE_IMAGE=busybox:1.36\n", encoding="utf-8")

    from_file = run_script(
        "scripts/image_inventory.py", "--compose", str(compose), "--env-file", str(env_file)
    )
    assert from_file.returncode == 0, from_file.stderr
    assert from_file.stdout.splitlines() == ["busybox:1.36"]

    from_process = run_script(
        "scripts/image_inventory.py",
        "--compose",
        str(compose),
        "--env-file",
        str(env_file),
        env={"PROBE_IMAGE": "redis:7-alpine"},
    )
    assert from_process.returncode == 0, from_process.stderr
    assert from_process.stdout.splitlines() == ["redis:7-alpine"]


STEP_CA = (
    "smallstep/step-ca:0.28.4@sha256:"
    "0f88382ac5af5c6b7bbba0c6e8fcefef52aee6f22ea364df8e02a09ffd0d22f3"
)
VAULT_BASE = (
    "hashicorp/vault:1.17.0@sha256:51e5f9b108e49aed025a27cbb66848911cb2bccee072057ba965b835a5427bce"
)


def test_overlays_add_their_images_to_the_base_set() -> None:
    """The union is additive per file and the single-file invocation is unchanged."""
    base = run_script(
        "scripts/image_inventory.py", "--compose", "docker-compose.yml", "--no-env-file"
    )
    assert base.returncode == 0, base.stderr
    base_images = base.stdout.splitlines()

    union = run_script(
        "scripts/image_inventory.py",
        "--compose",
        "docker-compose.yml",
        "--compose",
        "docker-compose.pki.yml",
        "--compose",
        "docker-compose.vault.yml",
        "--no-env-file",
    )
    assert union.returncode == 0, union.stderr
    images = union.stdout.splitlines()
    assert images[: len(base_images)] == base_images
    assert STEP_CA in images
    assert VAULT_BASE in images

    # The GPU overlay reuses the base image with another build target.
    gpu = run_script(
        "scripts/image_inventory.py",
        "--compose",
        "docker-compose.yml",
        "--compose",
        "docker-compose.gpu.yml",
        "--no-env-file",
    )
    assert gpu.returncode == 0, gpu.stderr
    assert gpu.stdout.splitlines() == base_images


def test_inventory_resolves_an_anchor_declared_overlay_image(tmp_path: Path) -> None:
    base = tmp_path / "docker-compose.yml"
    base.write_text("services:\n  a:\n    image: alpine:3.20\n", encoding="utf-8")
    overlay = tmp_path / "docker-compose.extra.yml"
    overlay.write_text(
        "x-extra-image: &extra-image\n"
        "  image: ghcr.io/example/sidecar:1.2.3\n"
        "  profiles: [extra]\n"
        "\n"
        "services:\n"
        "  sidecar:\n"
        "    <<: *extra-image\n"
        "  ephemeral:\n"
        "    image: busybox:1.36\n",
        encoding="utf-8",
    )

    both = run_script(
        "scripts/image_inventory.py",
        "--compose",
        str(base),
        "--compose",
        str(overlay),
        "--no-env-file",
    )
    assert both.returncode == 0, both.stderr
    assert both.stdout.splitlines() == [
        "alpine:3.20",
        "ghcr.io/example/sidecar:1.2.3",
        "busybox:1.36",
    ]

    # An overlay on its own is a valid inventory; before IDEA-055 this exited 2.
    overlay_only = run_script(
        "scripts/image_inventory.py", "--compose", str(overlay), "--no-env-file"
    )
    assert overlay_only.returncode == 0, overlay_only.stderr
    assert overlay_only.stdout.splitlines() == [
        "ghcr.io/example/sidecar:1.2.3",
        "busybox:1.36",
    ]


def test_an_overlay_required_variable_fails_closed(tmp_path: Path) -> None:
    base = tmp_path / "docker-compose.yml"
    base.write_text("services:\n  a:\n    image: alpine:3.20\n", encoding="utf-8")
    overlay = tmp_path / "docker-compose.extra.yml"
    overlay.write_text(
        "services:\n  b:\n    image: ${OVERLAY_TAG:?set OVERLAY_TAG}\n", encoding="utf-8"
    )
    result = run_script(
        "scripts/image_inventory.py",
        "--compose",
        str(base),
        "--compose",
        str(overlay),
        "--no-env-file",
    )
    assert result.returncode == 2
    assert "OVERLAY_TAG" in result.stderr


def test_a_build_only_service_contributes_its_dockerfile_base(tmp_path: Path) -> None:
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "Dockerfile").write_text(
        "FROM alpine:3.20 AS build\nFROM ghcr.io/example/app:2.0\n", encoding="utf-8"
    )
    overlay = tmp_path / "docker-compose.extra.yml"
    overlay.write_text(
        "services:\n  app:\n    build:\n      context: .\n      dockerfile: svc/Dockerfile\n",
        encoding="utf-8",
    )
    result = run_script("scripts/image_inventory.py", "--compose", str(overlay), "--no-env-file")
    assert result.returncode == 0, result.stderr
    # The last FROM is the image the Dockerfile produces.
    assert result.stdout.splitlines() == ["ghcr.io/example/app:2.0"]


def test_scan_images_covers_every_overlay_by_default(tmp_path: Path) -> None:
    """The documented command takes no arguments and still renders the union."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    scan = scripts / "scan_images.sh"
    scan.write_text(
        (ROOT / "scripts" / "scan_images.sh").read_text(encoding="utf-8"), encoding="utf-8"
    )
    scan.chmod(0o755)
    for overlay in ("docker-compose.yml", "docker-compose.pki.yml", "docker-compose.gpu.yml"):
        (tmp_path / overlay).write_text("services: {}\n", encoding="utf-8")
    log = tmp_path / "uv.log"
    binary = tmp_path / "bin"
    binary.mkdir()
    uv = binary / "uv"
    uv.write_text(
        "#!/bin/bash\n"
        f'echo "$*" >> "{log}"\n'
        'case "$*" in\n'
        "    *--required-vars*) ;;\n"
        "    *--compose*) printf '%s\\n' bastion-agent:local ;;\n"
        "    *--slug*) printf '%s\\n' bastion-agent-local ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    docker = binary / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        '    "image inspect "*) exit 0 ;;\n'
        '    "save "*) for last do :; done; touch "$last" ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    for path in (uv, docker):
        path.chmod(0o755)

    def run_scan(*args: str) -> None:
        log.write_text("", encoding="utf-8")
        result = subprocess.run(
            [str(scan), *args],
            cwd=tmp_path,
            env={**os.environ, "PATH": f"{binary}:{os.environ['PATH']}"},
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr

    run_scan()
    invocations = [
        line for line in log.read_text(encoding="utf-8").splitlines() if "--compose" in line
    ]
    # One call renders ${VAR:?} and one prints the inventory; both see the union.
    assert len(invocations) == 2, invocations
    assert sum("--required-vars" in line for line in invocations) == 1, invocations
    for line in invocations:
        assert "docker-compose.yml" in line, line
        assert "docker-compose.pki.yml" in line, line
        assert "docker-compose.gpu.yml" in line, line

    run_scan("--compose", "docker-compose.pki.yml")
    invocations = [
        line for line in log.read_text(encoding="utf-8").splitlines() if "--compose" in line
    ]
    assert invocations
    assert all("--compose docker-compose.pki.yml" in line for line in invocations)
    assert not any("docker-compose.gpu.yml" in line for line in invocations)


# ---------------------------------------------------------------------------
# CVE gate
# ---------------------------------------------------------------------------


def test_unignored_critical_fails(tmp_path: Path) -> None:
    report = write_report(tmp_path, "alpine-3.20", ["CVE-2024-0001", "CVE-2024-0002"])
    policy = write_policy(tmp_path, [ignore_entry()])
    result = run_script(
        "scripts/check_trivy_report.py",
        "--report",
        str(report),
        "--policy",
        str(policy),
        "--today",
        "2026-11-11",
    )
    assert result.returncode == 1
    assert "CVE-2024-0002" in result.stdout
    assert "1 suppressed, 1 unsuppressed" in result.stdout


def test_ignored_critical_passes(tmp_path: Path) -> None:
    report = write_report(tmp_path, "alpine-3.20", ["CVE-2024-0001"])
    policy = write_policy(tmp_path, [ignore_entry()])
    result = run_script(
        "scripts/check_trivy_report.py",
        "--report",
        str(report),
        "--policy",
        str(policy),
        "--today",
        "2026-11-11",
    )
    assert result.returncode == 0, result.stdout
    assert "1 suppressed, 0 unsuppressed" in result.stdout


def test_ignore_is_scoped_to_its_image(tmp_path: Path) -> None:
    report = write_report(tmp_path, "redis-7-alpine", ["CVE-2024-0001"])
    policy = write_policy(tmp_path, [ignore_entry(images=["alpine-3.20"])])
    result = run_script(
        "scripts/check_trivy_report.py",
        "--report",
        str(report),
        "--policy",
        str(policy),
        "--today",
        "2026-11-11",
    )
    assert result.returncode == 1
    assert "unsuppressed CRITICAL" in result.stdout


def test_expired_ignore_fails_even_when_unused(tmp_path: Path) -> None:
    report = write_report(tmp_path, "alpine-3.20", [])
    policy = write_policy(tmp_path, [ignore_entry(expires="2026-01-01")])
    result = run_script(
        "scripts/check_trivy_report.py",
        "--report",
        str(report),
        "--policy",
        str(policy),
        "--today",
        "2026-11-11",
    )
    assert result.returncode == 1
    assert "expired policy entries" in result.stdout


def test_policy_entry_needs_a_statement_and_expiry(tmp_path: Path) -> None:
    report = write_report(tmp_path, "alpine-3.20", [])
    entry = ignore_entry()
    del entry["statement"]
    policy = write_policy(tmp_path, [entry])
    result = run_script(
        "scripts/check_trivy_report.py",
        "--report",
        str(report),
        "--policy",
        str(policy),
        "--today",
        "2026-11-11",
    )
    assert result.returncode == 2
    assert "keys must be" in result.stderr


def test_policy_accepts_an_unquoted_yaml_date(tmp_path: Path) -> None:
    policy = tmp_path / "trivy.yaml"
    policy.write_text(
        "version: 1\n"
        "ignore:\n"
        "  - id: CVE-2024-0001\n"
        "    images: [alpine-3.20]\n"
        "    statement: 'Accepted until the next base image rebuild.'\n"
        "    expires: 2027-01-31\n",
        encoding="utf-8",
    )
    report = write_report(tmp_path, "alpine-3.20", ["CVE-2024-0001"])
    result = run_script(
        "scripts/check_trivy_report.py",
        "--report",
        str(report),
        "--policy",
        str(policy),
        "--today",
        "2026-11-11",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_non_critical_findings_do_not_fail(tmp_path: Path) -> None:
    report = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "alpine:3.20",
                "BastionImage": "alpine-3.20",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2024-0003", "Severity": "HIGH", "PkgName": "zlib"}
                ],
            }
        ],
    }
    path = tmp_path / "cve.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    policy = write_policy(tmp_path, [])
    result = run_script(
        "scripts/check_trivy_report.py",
        "--report",
        str(path),
        "--policy",
        str(policy),
        "--today",
        "2026-11-11",
    )
    assert result.returncode == 0, result.stdout
    assert "0 CRITICAL finding(s)" in result.stdout


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def test_aggregate_merges_sboms_and_tags_every_result(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    for index, name in enumerate(("alpine-3.20", "busybox-1.36")):
        (raw / f"{name}.cdx.json").write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [{"bom-ref": f"pkg:{name}", "name": name, "version": "1"}],
                    "vulnerabilities": [{"id": f"CVE-2024-000{index}", "affects": []}],
                }
            ),
            encoding="utf-8",
        )
        (raw / f"{name}.json").write_text(
            json.dumps(
                {
                    "SchemaVersion": 2,
                    "Results": [{"Target": "layer", "Vulnerabilities": []}],
                }
            ),
            encoding="utf-8",
        )

    out = tmp_path / "out"
    result = run_script(
        "scripts/aggregate_trivy_reports.py",
        "--raw",
        str(raw),
        "--out",
        str(out),
        "alpine:3.20",
        "busybox:1.36",
    )
    assert result.returncode == 0, result.stderr

    sbom = json.loads((out / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert {component["name"] for component in sbom["components"]} == {
        "alpine-3.20",
        "busybox-1.36",
    }
    assert len(sbom["vulnerabilities"]) == 2

    cve = json.loads((out / "cve.json").read_text(encoding="utf-8"))
    assert {item["BastionImage"] for item in cve["Results"]} == {"alpine-3.20", "busybox-1.36"}
    assert all("Target" in item for item in cve["Results"])

    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert [entry["reference"] for entry in manifest["images"]] == [
        "alpine:3.20",
        "busybox:1.36",
    ]


def test_aggregate_refuses_an_empty_raw_directory(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    result = run_script(
        "scripts/aggregate_trivy_reports.py",
        "--raw",
        str(raw),
        "--out",
        str(tmp_path / "out"),
        "alpine:3.20",
    )
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# Compose contract
# ---------------------------------------------------------------------------


def test_scanner_service_has_no_docker_socket_and_is_pinned() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    scanner = compose["services"]["trivy-scan"]
    assert not any("docker.sock" in str(volume) for volume in scanner.get("volumes", []))
    assert scanner["profiles"] == ["compliance"]
    assert scanner["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in scanner["security_opt"]
    assert "privileged" not in scanner
    assert "@sha256:" in scanner["image"]
    assert scanner.get("ports") is None


def test_scanner_is_not_in_the_default_profile() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert "trivy-scan" not in compose["services"]["gateway"]
    assert compose["services"]["trivy-scan"]["profiles"] == ["compliance"]


@pytest.mark.parametrize("path", ["trivy.yaml"])
def test_policy_file_is_valid(path: str) -> None:
    policy = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    assert policy["version"] == 1
    assert isinstance(policy["ignore"], list)


def test_a_policy_entry_can_suppress_an_overlay_only_image(tmp_path: Path) -> None:
    """An image only an overlay declares is scoped like any other."""
    slug = run_script("scripts/image_inventory.py", "--slug", STEP_CA).stdout.strip()
    assert slug == "smallstep-step-ca-0.28.4"
    report = write_report(tmp_path, slug, ["CVE-2026-0001"])

    policy = write_policy(tmp_path, [ignore_entry(vulnerability_id="CVE-2026-0001", images=[slug])])
    suppressed = run_script(
        "scripts/check_trivy_report.py",
        "--report",
        str(report),
        "--policy",
        str(policy),
        "--today",
        "2026-11-16",
    )
    assert suppressed.returncode == 0, suppressed.stdout

    # The same entry scoped to a different slug does not suppress it.
    policy = write_policy(
        tmp_path,
        [ignore_entry(vulnerability_id="CVE-2026-0001", images=["hashicorp-vault-1.17.0"])],
    )
    unsuppressed = run_script(
        "scripts/check_trivy_report.py",
        "--report",
        str(report),
        "--policy",
        str(policy),
        "--today",
        "2026-11-16",
    )
    assert unsuppressed.returncode == 1
    assert "unsuppressed CRITICAL" in unsuppressed.stdout


def test_the_scanner_is_never_given_an_ignorefile() -> None:
    """trivy.yaml stays the only suppression path, applied after the report."""
    scanner = (ROOT / "scripts" / "trivy-scan.sh").read_text(encoding="utf-8")
    assert "--ignorefile" not in scanner
