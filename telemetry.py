"""OpenTelemetry tracing for the gateway and worker.

Traces are exported over OTLP/HTTP to the local collector, which fans them out
to Langfuse and Arize. Configuration is entirely environment driven, so the same
image works with tracing on or off.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING

import httpx
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
from opentelemetry.trace import Span
from opentelemetry.util.types import AttributeValue

if TYPE_CHECKING:
    from opentelemetry.instrumentation.httpx import RequestInfo

from settings import Settings, get_settings

logger = logging.getLogger(__name__)

SERVICE_VERSION = "0.1.0"

#: Health probes and dashboard polls are excluded so they neither drown real
#: traffic nor exhaust a tracing backend's quota. The approvals queue is re-read
#: every 3 s and the evaluation card every 30 s, which is ~20 spans/min per open
#: dashboard for no diagnostic value (the queue has its own audit trail).
#:
#: ``ExcludeList`` matches the full URL with ``re.search``, so ``api/approvals$``
#: excludes the poll while ``POST /api/approvals/<ticket>/action`` — the
#: four-eyes decision, which is worth a span — stays traced.
DEFAULT_EXCLUDED_URLS = "/health,/health/ready,/metrics,api/approvals$,api/evals/latest$"

_provider: TracerProvider | None = None


def span_attributes(
    attributes: Mapping[str, AttributeValue | None],
) -> dict[str, AttributeValue]:
    """Drop unset values: OTel rejects ``None`` and warns once per attribute."""
    return {key: value for key, value in attributes.items() if value is not None}


def annotate_span(attributes: Mapping[str, AttributeValue | None]) -> None:
    """Attach machine metadata — never payload text — to the active span.

    Callers pass identifiers and verdicts, not prompt or tool argument content:
    traces leave the host, and a DLP product that exports payload text has moved
    the leak rather than stopped it.
    """
    trace.get_current_span().set_attributes(span_attributes(attributes))


def traces_endpoint(base_endpoint: str) -> str:
    """Normalise ``OTEL_EXPORTER_OTLP_ENDPOINT`` into an OTLP/HTTP traces URL."""
    base = base_endpoint.strip().rstrip("/")
    if not base:
        raise ValueError("OTEL_EXPORTER_OTLP_ENDPOINT must not be empty")
    if base.endswith("/v1/traces"):
        return base
    return f"{base}/v1/traces"


def configure_tracing(settings: Settings | None = None) -> TracerProvider | None:
    """Install the global tracer provider (idempotent)."""
    global _provider
    config = settings or get_settings()
    if not config.otel_enabled:
        logger.info("OpenTelemetry tracing disabled")
        return None
    if _provider is not None:
        return _provider
    if config.otel_traces_sampler_ratio <= 0.0:
        logger.warning("OTEL_TRACES_SAMPLER_RATIO is 0; spans will not be recorded")

    resource = Resource.create(
        {
            "service.name": config.otel_service_name,
            "service.version": SERVICE_VERSION,
            "service.namespace": "bastion-agent",
            "deployment.environment": config.environment,
        }
    )
    provider = TracerProvider(
        resource=resource,
        sampler=ParentBased(root=TraceIdRatioBased(config.otel_traces_sampler_ratio)),
    )
    exporter = OTLPSpanExporter(
        endpoint=traces_endpoint(config.otel_exporter_otlp_endpoint),
        timeout=10,
    )
    provider.add_span_processor(
        BatchSpanProcessor(
            exporter,
            max_queue_size=2048,
            schedule_delay_millis=2000,
            export_timeout_millis=10_000,
        )
    )
    trace.set_tracer_provider(provider)
    _provider = provider
    logger.info(
        "OpenTelemetry tracing configured",
        extra={
            "service_name": config.otel_service_name,
            "endpoint": traces_endpoint(config.otel_exporter_otlp_endpoint),
            "sampler_ratio": config.otel_traces_sampler_ratio,
        },
    )
    return provider


def instrument_app(app: FastAPI, *, excluded_urls: str = DEFAULT_EXCLUDED_URLS) -> None:
    """Attach automatic HTTP server spans to a FastAPI application."""
    if not get_settings().otel_enabled:
        return
    FastAPIInstrumentor.instrument_app(app, excluded_urls=excluded_urls)


async def _name_outbound_request(span: Span, request: RequestInfo) -> None:
    """Name a client span after the endpoint, not just the HTTP verb.

    The instrumentor names client spans ``POST``, which says nothing once the
    trace also contains an inbound ``POST /v1/chat``. This hook runs before the
    request, so the rename is exported with the span. It must never raise: an
    exception here would fail the request it is only supposed to observe.
    """
    raw_method = request.method
    method = raw_method.decode() if isinstance(raw_method, bytes) else str(raw_method)
    path = getattr(request.url, "path", "")
    span.update_name(f"{method.upper()} {path}".strip())


def instrument_http_client(
    client: httpx.AsyncClient,
    *,
    tracer_provider: TracerProvider | None = None,
) -> None:
    """Trace one outbound client's requests as children of the active span.

    Scoped to a client rather than the ``httpx`` module: the gateway uses the
    same library for Keycloak's JWKS and token endpoints, and tracing sign-ins
    would put auth noise in every model turn — the ASGI span already shows a
    rejected request. Only the model call is worth a wire-level span, and this
    way nothing else needs an exclusion list to stay quiet.

    ``tracer_provider`` is a test seam. Production leaves it unset: the tracer
    resolves the global provider lazily, so instrumenting a client before
    ``configure_tracing`` runs is safe.
    """
    HTTPXClientInstrumentor.instrument_client(
        client,
        tracer_provider=tracer_provider,
        request_hook=_name_outbound_request,
    )


def shutdown_tracing() -> None:
    """Flush pending spans and release the exporter (best effort)."""
    global _provider
    provider, _provider = _provider, None
    if provider is not None:
        provider.shutdown()
        logger.debug("OpenTelemetry tracing shut down")
