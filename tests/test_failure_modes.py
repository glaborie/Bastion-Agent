"""Deterministic fault injection through ``POST /v1/chat`` (ADR-004, IDEA-072).

Each test breaks one dependency boundary of the guarded turn and asserts the
whole outcome rather than a status code: the mapped 5xx, no model answer
released, no ``RESPONSE_SENT`` row, and the route the control chose. The audit
writer is a recorder, the vault and quarantine are fakeredis, and every fault
is deterministic, so the module needs no Postgres, no Redis container and no
Toxiproxy. No test waits on a real deadline: the configured OmniRoute timeout
is 50 ms and retries carry zero backoff.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any, cast

import httpx
import pytest
import pytest_asyncio
from fakeredis import FakeAsyncRedis
from redis.asyncio import Redis

from agent.dlp.presidio import PresidioDLP, get_analyzer
from agent.dlp.vault import TokenVault
from agent.egress.sanitizer import (
    EgressResult,
    EgressSanitizer,
    EgressUnavailableError,
)
from agent.routing.classifier import Classification, Sensitivity, SensitivityClassifier
from agent.routing.client import ModelRouter, OmniRouteClient
from db.models import AuditEventType
from db.session import get_db_session
from gateway.auth.oidc import Principal
from gateway.auth.rbac import AuthContext, get_auth_context
from gateway.main import create_app
from gateway.rate_limit import RateLimitDecision, RateLimitUnavailable, get_rate_limiter
from gateway.routers import chat as chat_module
from gateway.routers.chat import (
    get_chat_cache,
    get_chat_dlp,
    get_chat_router,
    get_chat_sanitizer,
)
from settings import get_settings, reset_settings_cache

KEY = b"f" * 32
PREFIX = "BASTION-CANARY-"
CONVERSATION = "conv-fault"
ANSWER = "A normal answer."
PII_TEXT = "Please email alice@example.com about the contract."

ALICE = Principal(
    subject="alice-sub", tenant_id="acme", username="alice", roles=frozenset({"operator"})
)
PUBLIC = Classification(Sensitivity.PUBLIC, 0.99, "stub-classifier", reason="public_content")


# -- doubles ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Row:
    """One audit record as the recorder saw it."""

    event_type: AuditEventType
    metadata: dict[str, Any]


@dataclass
class Ledger:
    """Audit-writer double: records rows and can fail one stage on demand."""

    rows: list[Row] = field(default_factory=list)
    fail_on: AuditEventType | None = None

    async def append(self, _session: object, **kwargs: Any) -> None:
        event_type: AuditEventType = kwargs["event_type"]
        if event_type is self.fail_on:
            raise ConnectionError("audit database unavailable")
        self.rows.append(Row(event_type, dict(kwargs.get("metadata_json") or {})))

    @property
    def types(self) -> list[AuditEventType]:
        return [row.event_type for row in self.rows]


class CommitOnlySession:
    """Stands in for ``AsyncSession``: ``_record`` only ever commits."""

    commits = 0

    async def commit(self) -> None:
        self.commits += 1


def _completion(request: httpx.Request) -> httpx.Response:
    model = json.loads(request.content)["model"]
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-fault",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": ANSWER},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
        },
    )


@dataclass
class Upstream:
    """``httpx`` transport double: records every attempt, answers or faults."""

    fault: Callable[[httpx.Request], httpx.Response] | None = None
    #: One entry per attempt, in order: the alias the request asked for.
    models: list[str] = field(default_factory=list)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.models.append(json.loads(request.content)["model"])
        return self.fault(request) if self.fault is not None else _completion(request)


@dataclass
class StubClassifier:
    """Classifier double: a fixed verdict, or an exception at request time."""

    classification: Classification = PUBLIC
    error: Exception | None = None

    def classify(self, text: str) -> Classification:
        return self.classification

    async def aclassify(self, text: str) -> Classification:
        if self.error is not None:
            raise self.error
        return self.classification


@dataclass
class StubLimiter:
    """Token-budget double: admits the request, can fail the reservation."""

    reserve_error: Exception | None = None

    async def consume(
        self,
        _principal_id: str,
        _scope: str,
        *,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitDecision:
        return RateLimitDecision(
            allowed=True,
            limit=limit,
            remaining=limit - cost,
            retry_after_seconds=0,
            reset_after_seconds=window_seconds,
        )

    async def reserve(
        self,
        _principal_id: str,
        *,
        tokens: int,
        capacity: int,
        window_seconds: int,
    ) -> RateLimitDecision:
        if self.reserve_error is not None:
            raise self.reserve_error
        return RateLimitDecision(
            allowed=True,
            limit=capacity,
            remaining=capacity - tokens,
            retry_after_seconds=0,
            reset_after_seconds=window_seconds,
        )

    async def settle(
        self,
        _principal_id: str,
        *,
        delta: int,
        capacity: int,
        window_seconds: int,
    ) -> int:
        return capacity


@dataclass
class UnreachableSanitizer:
    """Egress sanitizer whose store is down: the preflight works, the scan does not."""

    inner: EgressSanitizer

    async def ensure_available(self, tenant_id: str, session_id: str) -> None:
        await self.inner.ensure_available(tenant_id, session_id)

    async def canary_for(self, tenant_id: str, session_id: str) -> str:
        return await self.inner.canary_for(tenant_id, session_id)

    def with_canary(self, system_prompt: str, canary: str) -> str:
        return self.inner.with_canary(system_prompt, canary)

    def fence_untrusted(self, content: str, *, source: str = "tool") -> str:
        return self.inner.fence_untrusted(content, source=source)

    async def inspect(
        self,
        _text: str,
        _session_id: str,
        *,
        tenant_id: str,
        egress_session: str | None = None,
    ) -> EgressResult:
        raise EgressUnavailableError("egress sanitizer store is unreachable")


# -- harness ---------------------------------------------------------------


@dataclass
class Harness:
    client: httpx.AsyncClient
    app: Any
    ledger: Ledger
    upstream: Upstream
    classifier: StubClassifier
    sanitizer: EgressSanitizer
    session: CommitOnlySession


def _session_dependency(
    session: CommitOnlySession,
) -> Callable[[], AsyncIterator[CommitOnlySession]]:
    async def dependency() -> AsyncIterator[CommitOnlySession]:
        yield session

    return dependency


@pytest_asyncio.fixture
async def chat(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Harness]:
    """The real pipeline over a stubbed provider, with a recorder for the ledger."""
    monkeypatch.setenv("OMNIROUTE_TIMEOUT_SECONDS", "0.05")
    monkeypatch.setenv("OMNIROUTE_MAX_RETRIES", "2")
    reset_settings_cache()

    redis = FakeAsyncRedis(decode_responses=True)
    vault = TokenVault(redis, key=KEY, ttl_seconds=60)
    dlp = PresidioDLP(vault, analyzer=get_analyzer())
    sanitizer = EgressSanitizer(
        vault,
        cast(Redis, redis),
        canary_prefix=PREFIX,
        canary_ttl_seconds=60,
        trip_ttl_seconds=60,
    )
    ledger = Ledger()
    upstream = Upstream()
    classifier = StubClassifier()
    session = CommitOnlySession()
    settings = get_settings()
    http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    omni = OmniRouteClient(
        base_url="http://omniroute:20128",
        api_key="sk-test",
        timeout_seconds=settings.omniroute_timeout_seconds,
        max_retries=settings.omniroute_max_retries,
        retry_backoff_seconds=0,
        client=http,
    )
    monkeypatch.setattr(chat_module, "append_audit_event", ledger.append)

    app = create_app()
    app.dependency_overrides[get_auth_context] = lambda: AuthContext(
        principal=ALICE, method="bearer"
    )
    app.dependency_overrides[get_db_session] = _session_dependency(session)
    app.dependency_overrides[get_chat_router] = lambda: ModelRouter(
        cast(SensitivityClassifier, classifier), omni
    )
    app.dependency_overrides[get_chat_dlp] = lambda: dlp
    app.dependency_overrides[get_chat_sanitizer] = lambda: sanitizer
    app.dependency_overrides[get_chat_cache] = lambda: None

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        try:
            yield Harness(
                client=client,
                app=app,
                ledger=ledger,
                upstream=upstream,
                classifier=classifier,
                sanitizer=sanitizer,
                session=session,
            )
        finally:
            await http.aclose()
            await redis.aclose()


def body(content: str) -> dict[str, Any]:
    return {
        "conversation_id": CONVERSATION,
        "messages": [{"role": "user", "content": content}],
    }


def _connect_timeout(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectTimeout("connect timed out", request=request)


def _read_timeout(request: httpx.Request) -> httpx.Response:
    """A provider that sent headers and then stalled the body."""
    raise httpx.ReadTimeout("body read timed out", request=request)


def _connection_reset(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection reset by peer", request=request)


def _http_500(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(500, json={"error": {"code": "upstream_error"}})


def _http_429(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(429, json={"error": {"code": "rate_limited"}})


# -- provider faults -------------------------------------------------------


@pytest.mark.parametrize(
    ("fault", "expected_status"),
    [
        pytest.param(_connect_timeout, 504, id="connect-timeout"),
        pytest.param(_read_timeout, 504, id="slow-body"),
        pytest.param(_connection_reset, 504, id="connection-reset"),
        pytest.param(_http_500, 502, id="http-500"),
        pytest.param(_http_429, 502, id="http-429"),
    ],
)
async def test_upstream_faults_fail_closed(
    chat: Harness,
    fault: Callable[[httpx.Request], httpx.Response],
    expected_status: int,
) -> None:
    """A dead, slow or erroring provider returns 504/502 and no answer (ADR-004)."""
    chat.upstream.fault = fault

    response = await chat.client.post("/v1/chat", json=body("Explain what a message queue does."))

    assert response.status_code == expected_status, response.text
    assert ANSWER not in response.text
    # The retry budget is bounded by the setting and every attempt stays on the
    # alias the router chose.
    assert len(chat.upstream.models) == get_settings().omniroute_max_retries + 1
    assert set(chat.upstream.models) == {"cloud-primary"}
    # The turn stopped at the model stage: nothing was delivered, so the ledger
    # has no answer row to reconstruct.
    assert chat.ledger.types == [
        AuditEventType.INPUT_RECEIVED,
        AuditEventType.DLP_REDACTION,
        AuditEventType.ROUTING_DECISION,
    ]


async def test_a_pii_turn_fails_closed_and_never_reaches_the_cloud(chat: Harness) -> None:
    """DLP found an address, so a dead local route is an outage, not a failover."""
    chat.upstream.fault = _connection_reset

    response = await chat.client.post("/v1/chat", json=body(PII_TEXT))

    assert response.status_code == 503, response.text
    assert ANSWER not in response.text
    assert chat.upstream.models == ["local-llama"] * (get_settings().omniroute_max_retries + 1)
    incidents = [
        row for row in chat.ledger.rows if row.event_type is AuditEventType.SECURITY_INCIDENT
    ]
    assert [row.metadata["reason"] for row in incidents] == ["pii_route_local_unavailable"]
    assert incidents[0].metadata["stage"] == "model"
    assert incidents[0].metadata["route"] == "local-llama"
    assert AuditEventType.RESPONSE_SENT not in chat.ledger.types


async def test_a_faulted_turn_costs_one_short_deadline(chat: Harness) -> None:
    """No test waits out the 120 s production default or a retry backoff."""
    chat.upstream.fault = _read_timeout
    started = time.monotonic()

    response = await chat.client.post("/v1/chat", json=body("Explain what a message queue does."))

    elapsed = time.monotonic() - started
    assert response.status_code == 504, response.text
    assert get_settings().omniroute_timeout_seconds <= 0.1
    assert elapsed < 2.0


async def test_a_slow_stage_stops_at_the_request_deadline(
    chat: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deadline is checked between stages, not only around the model call."""
    monkeypatch.setenv("REQUEST_DEADLINE_SECONDS", "0.02")
    reset_settings_cache()
    real_dlp = chat.app.dependency_overrides[get_chat_dlp]()

    class SlowDLP:
        async def redact(self, *args: Any, **kwargs: Any) -> Any:
            await asyncio.sleep(0.1)  # the configured budget is 20 ms
            return await real_dlp.redact(*args, **kwargs)

    chat.app.dependency_overrides[get_chat_dlp] = SlowDLP

    response = await chat.client.post("/v1/chat", json=body("Explain what a message queue does."))

    assert response.status_code == 504, response.text
    assert response.json()["detail"] == "request deadline exceeded"
    assert chat.upstream.models == []
    assert AuditEventType.RESPONSE_SENT not in chat.ledger.types


# -- control-plane faults --------------------------------------------------


async def test_a_rate_limiter_outage_refuses_before_the_model(
    chat: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dead limiter store is a 503 before dispatch, not an unaccounted call."""
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    reset_settings_cache()
    chat.app.dependency_overrides[get_rate_limiter] = lambda: StubLimiter(
        reserve_error=RateLimitUnavailable("store is down")
    )

    response = await chat.client.post("/v1/chat", json=body("Explain what a message queue does."))

    assert response.status_code == 503, response.text
    assert response.json()["detail"] == "rate limiter unavailable"
    assert chat.upstream.models == []
    assert AuditEventType.RESPONSE_SENT not in chat.ledger.types


async def test_an_egress_sanitizer_outage_withholds_the_answer(chat: Harness) -> None:
    """Uninspected model text is never delivered: the answer existed, the caller sees 503."""
    chat.app.dependency_overrides[get_chat_sanitizer] = lambda: UnreachableSanitizer(chat.sanitizer)

    response = await chat.client.post("/v1/chat", json=body("Explain what a message queue does."))

    assert response.status_code == 503, response.text
    assert response.json()["detail"] == "egress sanitizer unavailable"
    assert ANSWER not in response.text
    assert chat.upstream.models == ["cloud-primary"]
    assert AuditEventType.RESPONSE_SENT not in chat.ledger.types


async def test_a_classifier_exception_refuses_the_turn(chat: Harness) -> None:
    """An unclassifiable prompt has no dependable route, so it is not sent at all."""
    chat.classifier.error = RuntimeError("onnx session crashed")

    response = await chat.client.post("/v1/chat", json=body("Explain what a message queue does."))

    assert response.status_code == 503, response.text
    assert response.json()["detail"] == "routing classifier unavailable"
    assert chat.upstream.models == []
    assert AuditEventType.RESPONSE_SENT not in chat.ledger.types


@pytest.mark.parametrize(
    ("fail_on", "upstream_calls"),
    [
        pytest.param(AuditEventType.ROUTING_DECISION, 0, id="before-the-model"),
        pytest.param(AuditEventType.EGRESS_FILTERED, 1, id="after-the-model"),
    ],
)
async def test_a_ledger_failure_delivers_nothing(
    chat: Harness, fail_on: AuditEventType, upstream_calls: int
) -> None:
    """An unauditable turn is a failed turn, whichever stage lost the database."""
    chat.ledger.fail_on = fail_on

    response = await chat.client.post("/v1/chat", json=body("Explain what a message queue does."))

    assert response.status_code == 500, response.text
    assert ANSWER not in response.text
    assert len(chat.upstream.models) == upstream_calls
    assert fail_on not in chat.ledger.types
    assert AuditEventType.RESPONSE_SENT not in chat.ledger.types
