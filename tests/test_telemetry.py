"""Telemetry configuration tests (no collector required)."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from opentelemetry.instrumentation.asgi import parse_excluded_urls
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agent.routing.client import OmniRouteClient
from settings import Settings
from telemetry import (
    DEFAULT_EXCLUDED_URLS,
    configure_tracing,
    instrument_http_client,
    span_attributes,
    traces_endpoint,
)


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


def test_outbound_call_is_a_child_span_named_after_its_endpoint() -> None:
    """The wire call hangs under the ``chat`` span and carries its status.

    A bare ``POST`` span beside an inbound ``POST /v1/chat`` says nothing, so
    the hook renames it. Only HTTP metadata is recorded: the body and the
    Authorization header stay out of the export.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))

    async def run() -> int:
        async with httpx.AsyncClient(transport=transport) as client:
            instrument_http_client(client, tracer_provider=provider)
            tracer = provider.get_tracer("test")
            with tracer.start_as_current_span("chat cloud-primary") as parent:
                await client.post(
                    "http://omniroute:4000/v1/chat/completions",
                    json={"model": "cloud-primary"},
                    headers={"Authorization": "Bearer sk-secret"},
                )
                return parent.get_span_context().span_id

    parent_id = asyncio.run(run())
    spans = {span.name: span for span in exporter.get_finished_spans()}
    assert set(spans) == {"chat cloud-primary", "POST /v1/chat/completions"}

    child = spans["POST /v1/chat/completions"]
    assert child.parent is not None
    assert child.parent.span_id == parent_id
    assert child.attributes["http.status_code"] == 200
    assert child.attributes["http.url"] == "http://omniroute:4000/v1/chat/completions"
    exported = repr(child.attributes)
    assert "sk-secret" not in exported and "cloud-primary" not in exported


def test_router_instruments_the_client_it_owns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Instrumenting the owned client is the wiring that makes the span exist."""
    seen: list[httpx.AsyncClient] = []
    monkeypatch.setattr("agent.routing.client.instrument_http_client", seen.append)
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200)))

    OmniRouteClient(base_url="http://omniroute:20128", api_key="sk-test", client=http)

    assert seen == [http]
    asyncio.run(http.aclose())
