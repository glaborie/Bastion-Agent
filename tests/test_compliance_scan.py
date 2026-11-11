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

# The nine shipped image references from IDEA-019's Problem statement.
EXPECTED_IMAGES = {
    "bastion-agent:local",
    "dpage/pgadmin4:9.19",
    "redis/redisinsight:3.8",
    "rigging/omniroute:3.8.52",
}
EXPECTED_IMAGE_PREFIXES = (
    "postgres:16-alpine@sha256:",
    "redis:7-alpine@sha256:",
    "quay.io/keycloak/keycloak:26.0@sha256:",
    "ghcr.io/ggml-org/llama.cpp:server-cuda@sha256:",
    "otel/opentelemetry-collector-contrib:0.111.0@sha256:",
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
    assert len(images) == 9
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


def test_inventory_excludes_a_service_that_only_exists_behind_compliance(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  shipped:\n"
        "    image: alpine:3.20\n"
        "  scanner:\n"
        "    image: ghcr.io/aquasecurity/trivy:0.76.1\n"
        "    profiles: [compliance]\n",
        encoding="utf-8",
    )
    result = run_script("scripts/image_inventory.py", "--compose", str(compose), "--no-env-file")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["alpine:3.20"]


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
    text = COMPOSE.read_text(encoding="utf-8")
    assert "docker.sock" not in text

    compose = yaml.safe_load(text)
    scanner = compose["services"]["trivy-scan"]
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
