"""Collector wiring tests for the opt-in Langfuse/Arize fan-out.

The collector is started with two ``--config`` files: the base definition and an
overlay that owns the traces pipeline's ``exporters`` list. Nothing at runtime
validates that pairing — a typo in an exporter name is a startup crash inside a
container, and a missing overlay silently reverts to local-only — so the three
files are checked here, without Docker.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Final

import pytest
import yaml

OTEL_DIR: Final[Path] = Path("config/otel")
BASE: Final[Path] = OTEL_DIR / "otel-collector-config.yaml"
EXPORT: Final[Path] = OTEL_DIR / "otel-collector-export.yaml"
NO_EXPORT: Final[Path] = OTEL_DIR / "otel-collector-no-export.yaml"
OPIK: Final[Path] = OTEL_DIR / "otel-collector-opik.yaml"
COMPOSE: Final[Path] = Path("docker-compose.yml")


def load(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{path} is not a mapping"
    return document


def pipeline_exporters(document: dict[str, Any]) -> list[str]:
    exporters = document["service"]["pipelines"]["traces"]["exporters"]
    assert isinstance(exporters, list)
    return [str(name) for name in exporters]


def test_base_definition_owns_the_remote_exporter_settings() -> None:
    """The overlays only choose *which* exporters run; the base defines them."""
    exporters = load(BASE)["exporters"]
    assert set(exporters) >= {"debug", "otlphttp/langfuse", "otlphttp/arize", "otlphttp/opik"}

    langfuse = exporters["otlphttp/langfuse"]
    assert langfuse["endpoint"] == "${env:LANGFUSE_OTLP_ENDPOINT}"
    assert langfuse["headers"]["Authorization"] == "Basic ${env:LANGFUSE_OTLP_AUTH}"
    # Langfuse and Arize ingest JSON, not the exporter's default protobuf.
    assert langfuse["encoding"] == "json"

    arize = exporters["otlphttp/arize"]
    assert arize["endpoint"] == "${env:ARIZE_OTLP_ENDPOINT}"
    assert arize["encoding"] == "json"
    # Arize's ingest does not gunzip; the exporter default answers 400 per batch.
    assert arize["compression"] == "none"
    assert arize["headers"]["x-project-name"] == "${env:ARIZE_PROJECT_NAME}"

    # Opik Cloud is a real OTLP endpoint, so it takes the exporter defaults
    # (protobuf, gzip) — only the endpoint and the three routing/auth headers.
    opik = exporters["otlphttp/opik"]
    assert opik["endpoint"] == "${env:OPIK_OTLP_ENDPOINT}"
    assert opik["headers"]["Authorization"] == "${env:OPIK_API_KEY}"
    assert opik["headers"]["Comet-Workspace"] == "${env:OPIK_WORKSPACE}"
    assert opik["headers"]["projectName"] == "${env:OPIK_PROJECT_NAME}"


def test_opik_overlay_sends_traces_off_the_host() -> None:
    """Opik Cloud is the cloud option, selected without touching the base file."""
    assert pipeline_exporters(load(OPIK)) == ["debug", "otlphttp/opik"]

    text = COMPOSE.read_text(encoding="utf-8")
    assert (
        "OPIK_OTLP_ENDPOINT: ${OPIK_OTLP_ENDPOINT:-https://www.comet.com/opik/api/v1/private/otel}"
        in (text)
    )
    assert "OPIK_API_KEY: ${OPIK_API_KEY:-}" in text
    # The endpoint is a cloud URL; no host-gateway mapping is needed for it, and
    # keeping one would suggest a local collector that no longer exists.
    assert "host.docker.internal" not in text


@pytest.mark.parametrize("overlay", [EXPORT, NO_EXPORT, OPIK], ids=["export", "no-export", "opik"])
def test_overlays_only_name_exporters_the_base_defines(overlay: Path) -> None:
    defined = set(load(BASE)["exporters"])
    named = set(pipeline_exporters(load(overlay)))
    assert named <= defined, f"{overlay} names an exporter the base does not define"
    # The overlay must not restate the receivers or processors: a missing key
    # here would otherwise silently drop OTLP input or the memory limiter.
    traces = load(overlay)["service"]["pipelines"]["traces"]
    assert set(traces) == {"exporters"}


def test_default_overlay_keeps_egress_local() -> None:
    assert pipeline_exporters(load(NO_EXPORT)) == ["debug"]


def test_export_overlay_fans_out_to_both_backends() -> None:
    assert pipeline_exporters(load(EXPORT)) == [
        "debug",
        "otlphttp/langfuse",
        "otlphttp/arize",
    ]


def test_pipeline_drops_caller_controlled_noise() -> None:
    """ASGI event spans and 404s must not reach a metered backend.

    A client polling an unimplemented route produced ~11,500 spans/day in the
    Arize project on 2026-11-10 (40:1 noise against real traffic), and that
    volume is caller-controlled. The filter is the only thing standing between
    an unauthenticated path scanner and the export quota.
    """
    processors = load(BASE)["processors"]
    rules = processors["filter/noise"]["traces"]["span"]
    assert any("http (send|receive)" in rule for rule in rules), rules
    assert any('"http.status_code"] == 404' in rule for rule in rules), rules
    assert any('"http.response.status_code"] == 404' in rule for rule in rules), rules

    pipeline = load(BASE)["service"]["pipelines"]["traces"]["processors"]
    assert pipeline.index("filter/noise") < pipeline.index("batch"), pipeline


def test_opik_endpoint_stays_a_base_url() -> None:
    """The exporter appends /v1/traces; the SDK-doc form is a silent no-op.

    Opik's SDK examples set ``OTEL_EXPORTER_OTLP_ENDPOINT`` to the signal URL
    (``.../otel/v1/traces``) because the Python exporter does not append the
    path. The collector's ``otlphttp`` exporter does, so copying that value
    yields ``.../otel/v1/traces/v1/traces`` and every batch is rejected.
    """
    text = COMPOSE.read_text(encoding="utf-8")
    match = re.search(r"OPIK_OTLP_ENDPOINT: \$\{OPIK_OTLP_ENDPOINT:-([^}]+)\}", text)
    assert match, "docker-compose.yml no longer defaults OPIK_OTLP_ENDPOINT"
    assert match.group(1).rstrip("/").endswith("/api/v1/private/otel"), match.group(1)
    example = Path(".env.example").read_text(encoding="utf-8")
    assert "\nOPIK_OTLP_ENDPOINT=https://www.comet.com/opik/api/v1/private/otel\n" in example
    assert "\nOPIK_API_KEY=\n" in example
    assert "\nOPIK_WORKSPACE=default\n" in example
    assert "\nOPIK_PROJECT_NAME=bastion\n" in example


def test_arize_endpoint_stays_a_base_url() -> None:
    """The exporter appends /v1/traces; a /v1 endpoint is a silent no-op.

    ``https://otlp.arize.com/v1/v1/traces`` answers 200 "ok" and drops the
    batch, so a wrong value here still looks like a healthy export in the
    collector log.
    """
    text = COMPOSE.read_text(encoding="utf-8")
    match = re.search(r"ARIZE_OTLP_ENDPOINT: \$\{ARIZE_OTLP_ENDPOINT:-([^}]+)\}", text)
    assert match, "docker-compose.yml no longer defaults ARIZE_OTLP_ENDPOINT"
    assert not match.group(1).rstrip("/").endswith("/v1"), match.group(1)
    example = Path(".env.example").read_text(encoding="utf-8")
    assert "\nARIZE_OTLP_ENDPOINT=https://otlp.arize.com\n" in example


def test_compose_merges_both_configs_and_selects_the_overlay_by_name() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    assert '"--config=/etc/otelcol/config.yaml", "--config=/etc/otelcol/export.yaml"' in text
    match = re.search(
        r"\./config/otel/\$\{OTEL_REMOTE_EXPORT_CONFIG:-([\w.-]+)\}:"
        r"/etc/otelcol/export\.yaml:ro",
        text,
    )
    assert match, "docker-compose.yml no longer mounts the overlay"
    assert (OTEL_DIR / match.group(1)).is_file()
    assert match.group(1) == NO_EXPORT.name, "the default must not export remotely"
