"""Telemetry configuration tests (no collector required)."""

from __future__ import annotations

import pytest
from opentelemetry.instrumentation.asgi import parse_excluded_urls

from settings import Settings
from telemetry import DEFAULT_EXCLUDED_URLS, configure_tracing, span_attributes, traces_endpoint


def test_span_attributes_drop_unset_values() -> None:
    """OTel warns once per ``None`` attribute and shows null in the backend."""
    assert span_attributes({"kept": 1, "dropped": None, "false": False}) == {
        "kept": 1,
        "false": False,
    }


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


def test_dashboard_polls_are_excluded_but_decisions_are_traced() -> None:
    """A 3 s poll must not generate spans; the four-eyes decision should.

    Evaluated through the parser the ASGI middleware actually uses, so the
    trailing ``$`` semantics are the ones production gets.
    """
    excluded = parse_excluded_urls(DEFAULT_EXCLUDED_URLS)
    assert excluded.url_disabled("http://localhost:8000/api/approvals")
    assert excluded.url_disabled("http://localhost:8000/api/evals/latest")
    assert not excluded.url_disabled(
        "http://localhost:8000/api/approvals/9624899a-294e-452d-b60d-e84e24593a96/action"
    )


def test_disabled_tracing_is_a_noop() -> None:
    settings = Settings(_env_file=None, otel_enabled=False)  # type: ignore[call-arg]
    assert configure_tracing(settings) is None
