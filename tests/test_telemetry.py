"""Telemetry configuration tests (no collector required)."""

from __future__ import annotations

import pytest

from settings import Settings
from telemetry import DEFAULT_EXCLUDED_URLS, configure_tracing, traces_endpoint


def test_traces_endpoint_appends_the_signal_path() -> None:
    assert traces_endpoint("http://otel-collector:4318") == ("http://otel-collector:4318/v1/traces")
    assert traces_endpoint("http://otel-collector:4318/") == (
        "http://otel-collector:4318/v1/traces"
    )


def test_traces_endpoint_is_idempotent() -> None:
    explicit = "https://collector.example/v1/traces"
    assert traces_endpoint(explicit) == explicit


def test_traces_endpoint_rejects_empty_configuration() -> None:
    with pytest.raises(ValueError, match="OTEL_EXPORTER_OTLP_ENDPOINT"):
        traces_endpoint("   ")


def test_health_probes_are_excluded_from_spans() -> None:
    assert "/health" in DEFAULT_EXCLUDED_URLS.split(",")
    assert "/health/ready" in DEFAULT_EXCLUDED_URLS.split(",")


def test_disabled_tracing_is_a_noop() -> None:
    settings = Settings(_env_file=None, otel_enabled=False)  # type: ignore[call-arg]
    assert configure_tracing(settings) is None
