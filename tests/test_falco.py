"""Falco runtime-detection contract tests.

The live triggers are exercised by ``scripts/falco_smoke.sh`` against a running
stack. These tests pin the properties that must hold without a privileged
container: the compose carve-out, the rule set, the alert-field allow-list and
the allowlist review dates.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "docker-compose.yml"
RULES = ROOT / "config" / "falco" / "bastion_rules.yaml"
ALLOWLIST = ROOT / "config" / "falco" / "ALLOWLIST.md"
FALCO_IMAGE = "falcosecurity/falco:0.45.2"
DOCKER = shutil.which("docker")

EXPECTED_RULES = {
    "Bastion shell spawned in an application container",
    "Bastion worker write outside the tool workspace",
    "Bastion gateway egress outside the allowlist",
    "Bastion shell or nsenter in a data container",
    "Bastion write to a sensitive system file",
    "Bastion application source tree modified",
}
FORBIDDEN_OUTPUT_FIELDS = (
    "%proc.cmdline",
    "%proc.args",
    "%proc.env",
    "%evt.buffer",
    "%evt.arg.data",
)
REVIEW_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def load_compose() -> dict[str, Any]:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(compose, dict)
    return compose


def load_rules() -> list[dict[str, Any]]:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    assert isinstance(rules, list)
    return rules


def test_falco_is_an_opt_in_privileged_carve_out() -> None:
    services = load_compose()["services"]
    falco = services["falco"]
    assert falco["profiles"] == ["security"]
    assert falco["privileged"] is True
    assert "@sha256:" in falco["image"]
    assert "pid" not in falco
    assert [name for name, service in services.items() if service.get("privileged")] == ["falco"]


def test_docker_socket_is_mounted_only_for_falco_and_read_only() -> None:
    services = load_compose()["services"]
    for name, service in services.items():
        for volume in service.get("volumes", []) or []:
            if "docker.sock" in str(volume):
                assert name == "falco", f"{name} must not mount the engine socket"
                assert str(volume).endswith(":ro"), "the socket must be read-only"
                assert "/host/var/run/docker.sock" in str(volume)
    falco_volumes = " ".join(str(volume) for volume in services["falco"]["volumes"])
    assert "/dev:/host/dev" in falco_volumes
    assert "/sys/kernel/tracing" in falco_volumes


def test_falco_does_not_change_the_default_stack() -> None:
    services = load_compose()["services"]
    assert services["falco"]["profiles"] == ["security"]
    for name in ("gateway", "worker", "db", "redis", "keycloak", "omniroute", "llama-cpp"):
        assert "falco" not in services[name].get("depends_on", {})


def test_rules_cover_the_documented_behaviours() -> None:
    rules = load_rules()
    names = {rule["rule"] for rule in rules}
    assert names == EXPECTED_RULES
    for rule in rules:
        assert rule["condition"].strip()
        assert rule["priority"] in {"WARNING", "CRITICAL"}
        assert "bastion" in rule["tags"]


def test_alert_output_never_carries_payload_text() -> None:
    for rule in load_rules():
        output = rule["output"]
        for field in FORBIDDEN_OUTPUT_FIELDS:
            assert field not in output, f"{rule['rule']} exports {field}"


def test_worker_rule_is_workspace_and_tmp_scoped() -> None:
    rule = next(r for r in load_rules() if "worker write" in r["rule"])
    condition = rule["condition"]
    assert 'startswith "bastion-agent-worker"' in condition
    assert "not fd.name startswith /tmp" in condition


def test_gateway_rule_allowlists_the_internal_ports() -> None:
    rule = next(r for r in load_rules() if "gateway egress" in r["rule"])
    condition = rule["condition"]
    for port in (53, 4317, 4318, 5432, 6379, 8000, 8080, 20128):
        assert str(port) in condition


def test_every_exception_has_a_reviewed_allowlist_row() -> None:
    exceptions = [exception for rule in load_rules() for exception in rule.get("exceptions", [])]
    assert exceptions, "at least one baseline exception should be documented"
    text = ALLOWLIST.read_text(encoding="utf-8")
    today = datetime.now(UTC).date()
    for exception in exceptions:
        name = exception["name"]
        row = next((line for line in text.splitlines() if f"`{name}`" in line), None)
        assert row is not None, f"{name} is missing from ALLOWLIST.md"
        match = REVIEW_DATE.search(row)
        assert match is not None, f"{name} has no review date"
        assert datetime.fromisoformat(match.group(1)).date() >= today, (
            f"{name} review date has passed"
        )


def _falco_image_present() -> bool:
    if DOCKER is None:
        return False
    result = subprocess.run(
        [DOCKER, "image", "inspect", FALCO_IMAGE],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


@pytest.mark.skipif(not _falco_image_present(), reason="Falco image is not present locally")
def test_rules_and_config_validate_in_the_falco_image() -> None:
    assert DOCKER is not None
    result = subprocess.run(
        [
            DOCKER,
            "run",
            "--rm",
            "--entrypoint",
            "/usr/bin/falco",
            "-v",
            f"{RULES}:/rules/bastion.yaml:ro",
            FALCO_IMAGE,
            "-V",
            "/etc/falco/falco_rules.yaml",
            "-V",
            "/rules/bastion.yaml",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
