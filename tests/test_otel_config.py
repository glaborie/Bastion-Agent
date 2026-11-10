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
    assert set(exporters) >= {"debug", "otlphttp/langfuse", "otlphttp/arize"}

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


@pytest.mark.parametrize("overlay", [EXPORT, NO_EXPORT], ids=["export", "no-export"])
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
