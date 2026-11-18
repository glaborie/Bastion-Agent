"""The opt-in availability monitor: compose posture, monitor set and the seed.

The live container is exercised by hand (and documented in ``README.md``); these
tests pin the parts that must not drift without a reviewer noticing: the service
stays behind its profile with no engine socket, the committed monitor set covers
every probe the outcome names, the seed converges instead of duplicating, and no
admin credential is committed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts import seed_uptime_kuma
from scripts.seed_uptime_kuma import MONITOR_DEFAULTS, monitor_payload, seed

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
MONITORS = ROOT / "config" / "uptime-kuma" / "monitors.json"
ENV_EXAMPLE = ROOT / ".env.example"

# The default stack, unchanged by this sidecar: no profile means `up` starts it.
DEFAULT_SERVICES = {
    "db",
    "gateway",
    "keycloak",
    "llama-cpp",
    "migrate",
    "models-init",
    "omniroute",
    "otel-collector",
    "redis",
    "worker",
}

PROBE_NAMES = {
    "gateway /health",
    "gateway /health/ready",
    "db :5432",
    "redis :6379",
    "keycloak :9000/health",
    "omniroute /api/health",
    "llama-cpp :8080",
}


def compose() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    return loaded


def monitor_file() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(MONITORS.read_text(encoding="utf-8"))
    return loaded


def test_the_default_stack_stays_the_same_set() -> None:
    services = compose()["services"]
    started_by_default = {name for name, service in services.items() if not service.get("profiles")}
    assert started_by_default == DEFAULT_SERVICES
    assert services["uptime-kuma"]["profiles"] == ["infra"]


def test_the_monitor_is_pinned_loopback_only_and_stripped() -> None:
    service = compose()["services"]["uptime-kuma"]

    assert service["image"].startswith("louislam/uptime-kuma:2.5.12@sha256:")
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert not service.get("privileged", False)
    # Non-root: the image's data dir is owned by uid 1000, and root cannot keep
    # writing it once every capability is dropped.
    assert service["user"]
    assert service["volumes"] == ["uptimekuma_data:/app/data"]
    assert "uptimekuma_data" in compose()["volumes"]

    ports = service["ports"]
    assert len(ports) == 1
    assert str(ports[0]).startswith("127.0.0.1:")
    assert str(ports[0]).endswith(":3001")


def test_no_service_but_falco_mounts_the_engine_socket() -> None:
    """A socket is host-root-equivalent; ADR-017 spends the one exception."""
    services = compose()["services"]
    socket_mounts = {
        name: [volume for volume in service.get("volumes") or [] if "docker.sock" in str(volume)]
        for name, service in services.items()
    }
    assert {name: mounts for name, mounts in socket_mounts.items() if mounts} == {
        "falco": ["/var/run/docker.sock:/host/var/run/docker.sock:ro"]
    }
    assert "docker.sock" not in json.dumps(services["uptime-kuma"])


def test_the_committed_monitor_set_covers_every_probe() -> None:
    entries = {entry["name"]: entry for entry in monitor_file()["monitors"]}
    assert set(entries) == PROBE_NAMES
    for name, entry in entries.items():
        assert entry["type"] in {"http", "port"}, name
        assert entry["interval"] >= 20, name
        if entry["type"] == "http":
            assert entry["url"].startswith("http://"), name
        else:
            assert entry["hostname"] and entry["port"], name
    # A slow local model needs a grace long enough to survive a load.
    llama = entries["llama-cpp :8080"]
    assert llama["maxretries"] * llama["retryInterval"] >= 300


def test_the_worker_is_recorded_as_unmonitored() -> None:
    unmonitored = {entry["service"]: entry for entry in monitor_file()["unmonitored"]}
    assert "worker" in unmonitored
    assert len(unmonitored["worker"]["reason"]) > 20
    assert "worker" not in {entry["name"] for entry in monitor_file()["monitors"]}


class RecordingClient:
    """A ``MonitorClient`` that remembers what it was asked to create."""

    def __init__(self) -> None:
        self.known: dict[str, dict[str, Any]] = {}
        self.added: list[str] = []

    def connect(self) -> None:
        return

    def monitors(self) -> dict[str, dict[str, Any]]:
        return self.known

    def add_monitor(self, monitor: dict[str, Any]) -> int:
        self.known[monitor["name"]] = monitor
        self.added.append(monitor["name"])
        return len(self.known)


def test_the_seed_is_idempotent() -> None:
    spec = monitor_file()
    client = RecordingClient()

    added, kept = seed(client, spec)
    assert added == [entry["name"] for entry in spec["monitors"]]
    assert not kept
    first = set(client.known)

    added, kept = seed(client, spec)
    assert not added
    assert set(kept) == first
    assert set(client.known) == first


def test_the_payload_carries_every_field_add_reads() -> None:
    payload = monitor_payload(
        {"name": "x", "type": "http", "url": "http://x", "_comment": "drop me"}
    )
    # `add` reads these before importing the bean; a missing key is a server-side
    # TypeError rather than a validation message.
    for field in (
        "accepted_statuscodes",
        "kafkaProducerBrokers",
        "conditions",
        "rabbitmqNodes",
        "notificationIDList",
    ):
        assert field in payload
    assert payload["name"] == "x"
    assert payload["accepted_statuscodes"] == MONITOR_DEFAULTS["accepted_statuscodes"]
    assert "_comment" not in payload


def test_the_admin_credential_has_no_committed_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The container has no use for it; the seed reads it on the host.
    assert "UPTIME_KUMA_ADMIN_PASSWORD" not in json.dumps(compose()["services"]["uptime-kuma"])

    env_example = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "\nUPTIME_KUMA_ADMIN_PASSWORD=\n" in env_example

    # Fail on a literal: every committed assignment of the key is empty, and the
    # seed refuses to run without one.
    literals = [
        line.strip()
        for path in (ENV_EXAMPLE, COMPOSE)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("UPTIME_KUMA_ADMIN_PASSWORD=")
        and line.strip() != "UPTIME_KUMA_ADMIN_PASSWORD="
    ]
    assert literals == []

    monkeypatch.delenv("UPTIME_KUMA_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(seed_uptime_kuma, "ENV_FILE", tmp_path / "missing.env")
    assert seed_uptime_kuma.main([]) == 2
