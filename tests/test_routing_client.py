"""OmniRoute client and model routing tests (ADR-004)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
import yaml

from agent.routing.classifier import Classification, Sensitivity, SensitivityClassifier
from agent.routing.client import (
    BreakerOpenError,
    ChatMessage,
    ModelRouter,
    OmniRouteClient,
    RequestDeadline,
    RouteBusyError,
    RoutingError,
    UpstreamError,
    UpstreamResponseError,
    UpstreamTimeoutError,
)
from settings import get_settings


class StubClassifier:
    def __init__(self, classification: Classification) -> None:
        self.classification = classification

    def classify(self, text: str) -> Classification:
        return self.classification

    async def aclassify(self, text: str) -> Classification:
        return self.classification


def public() -> Classification:
    return Classification(Sensitivity.PUBLIC, 0.1, "semantic-rules")


def confidential() -> Classification:
    return Classification(Sensitivity.CONFIDENTIAL, 0.9, "semantic-rules")


def completion_payload(model: str = "cloud-primary", content: str = "hello") -> dict[str, Any]:
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 2,
            "total_tokens": 12,
            # OmniRoute reports the provider's USD cost per completion.
            "cost": 2.55e-06,
        },
    }


def build_client(
    handler: Any,
    *,
    max_retries: int = 0,
) -> tuple[OmniRouteClient, httpx.AsyncClient]:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OmniRouteClient(
        base_url="http://omniroute:20128",
        api_key="sk-test",
        max_retries=max_retries,
        retry_backoff_seconds=0,
        client=http,
    )
    return client, http


def router(classification: Classification, client: OmniRouteClient) -> ModelRouter:
    return ModelRouter(
        cast(SensitivityClassifier, StubClassifier(classification)),
        client,
        local_alias="local-llama",
        cloud_alias="cloud-primary",
    )


async def test_confidential_prompts_route_to_the_local_alias() -> None:
    client, http = build_client(lambda request: httpx.Response(200, json={}))
    try:
        decision = router(confidential(), client).route("anything")
    finally:
        await http.aclose()
    assert decision.alias == "local-llama"
    assert decision.local is True


async def test_public_prompts_route_to_the_cloud_alias() -> None:
    client, http = build_client(lambda request: httpx.Response(200, json={}))
    try:
        decision = router(public(), client).route("anything")
    finally:
        await http.aclose()
    assert decision.alias == "cloud-primary"
    assert decision.local is False
    assert decision.override is None


async def test_a_dlp_hit_keeps_a_public_prompt_on_the_local_model() -> None:
    """ADR-002 decision 3: the classifier verdict is kept, the route is not."""
    client, http = build_client(lambda request: httpx.Response(200, json={}))
    try:
        decision = await router(public(), client).aroute("anything", pii_detected=True)
    finally:
        await http.aclose()
    assert decision.alias == "local-llama"
    assert decision.local is True
    assert decision.override == "pii_detected"
    assert decision.classification.label is Sensitivity.PUBLIC


async def test_confidential_traffic_is_not_marked_as_a_pii_override() -> None:
    client, http = build_client(lambda request: httpx.Response(200, json={}))
    try:
        decision = await router(confidential(), client).aroute("anything", pii_detected=True)
    finally:
        await http.aclose()
    assert decision.alias == "local-llama"
    assert decision.override is None


def test_pinned_model_mirrors_the_omniroute_combos() -> None:
    """Telemetry names a concrete model per alias; drift would mislabel traces.

    The agent reports the first target of each OmniRoute combo as the requested
    model (config/omniroute/config.yaml is the routing source of truth), so the
    two must agree without anyone remembering to edit both.
    """
    config = yaml.safe_load(Path("config/omniroute/config.yaml").read_text(encoding="utf-8"))
    combos = config["combos"]
    settings = get_settings()

    for alias, pinned in (
        ("local-llama", settings.model_local_primary),
        ("cloud-primary", settings.model_cloud_primary),
    ):
        first_target = combos[alias]["models"][0]
        # OmniRoute prefixes the router node ("openrouter/", "llama/"); the
        # setting stores the target with that prefix stripped.
        assert first_target.split("/", 1)[1] == pinned, (alias, first_target, pinned)


async def test_completion_payload_and_auth_header() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json=completion_payload())

    client, http = build_client(handler)
    try:
        result = await client.chat_completion(
            [
                ChatMessage("system", "be brief"),
                ChatMessage("user", "hello", name="alice"),
            ],
            model="cloud-primary",
            temperature=0.2,
            max_tokens=64,
        )
    finally:
        await http.aclose()

    assert result.content == "hello"
    assert result.model == "cloud-primary"
    assert result.total_tokens == 12
    assert result.cost_usd == pytest.approx(2.55e-06)
    assert result.finish_reason == "stop"

    request = captured[0]
    assert str(request.url) == "http://omniroute:20128/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer sk-test"
    body = json.loads(request.content)
    assert body["model"] == "cloud-primary"
    assert body["temperature"] == 0.2
    assert body["max_tokens"] == 64
    assert body["stream"] is False
    assert body["messages"][1] == {"role": "user", "content": "hello", "name": "alice"}


async def test_max_tokens_is_omitted_when_not_set() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert "max_tokens" not in body
        return httpx.Response(200, json=completion_payload())

    client, http = build_client(handler)
    try:
        await client.chat_completion([ChatMessage("user", "hi")], model="cloud-primary")
    finally:
        await http.aclose()


async def test_complete_classifies_the_last_user_message() -> None:
    seen: list[str] = []

    class RecordingClassifier(StubClassifier):
        def classify(self, text: str) -> Classification:
            seen.append(text)
            return self.classification

        async def aclassify(self, text: str) -> Classification:
            return self.classify(text)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=completion_payload(model="local-llama"))

    client, http = build_client(handler)
    model_router = ModelRouter(
        cast(SensitivityClassifier, RecordingClassifier(confidential())),
        client,
    )
    try:
        result = await model_router.complete(
            [ChatMessage("system", "system"), ChatMessage("user", "the last user turn")]
        )
    finally:
        await http.aclose()
    assert seen == ["the last user turn"]
    assert result.model == "local-llama"


async def test_conversation_without_a_user_message_is_rejected() -> None:
    client, _http = build_client(lambda request: httpx.Response(200, json={}))
    try:
        with pytest.raises(RoutingError, match="user message"):
            await router(public(), client).complete([ChatMessage("system", "only system")])
    finally:
        await _http.aclose()


async def test_non_retryable_status_is_not_retried() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(400, json={"error": {"code": "invalid_request", "message": "bad"}})

    client, http = build_client(handler, max_retries=2)
    try:
        with pytest.raises(UpstreamError) as info:
            await client.chat_completion([ChatMessage("user", "hi")], model="cloud-primary")
    finally:
        await http.aclose()
    assert calls["n"] == 1
    assert info.value.status_code == 400
    assert info.value.code == "invalid_request"


async def test_retryable_status_is_retried() -> None:
    responses = [
        httpx.Response(503, json={"error": "busy"}),
        httpx.Response(200, json=completion_payload()),
    ]
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        response = responses[min(calls["n"], len(responses) - 1)]
        calls["n"] += 1
        return response

    client, http = build_client(handler, max_retries=1)
    try:
        result = await client.chat_completion([ChatMessage("user", "hi")], model="cloud-primary")
    finally:
        await http.aclose()
    assert calls["n"] == 2
    assert result.content == "hello"


async def test_transport_error_is_retried() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(200, json=completion_payload())

    client, http = build_client(handler, max_retries=1)
    try:
        result = await client.chat_completion([ChatMessage("user", "hi")], model="cloud-primary")
    finally:
        await http.aclose()
    assert calls["n"] == 2
    assert result.content == "hello"


async def test_malformed_response_is_rejected() -> None:
    client, http = build_client(lambda request: httpx.Response(200, json={"choices": []}))
    try:
        with pytest.raises(UpstreamResponseError, match="no choices"):
            await client.chat_completion([ChatMessage("user", "hi")], model="cloud-primary")
    finally:
        await http.aclose()


async def test_confidential_traffic_never_falls_back_to_cloud() -> None:
    models: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        models.append(json.loads(request.content)["model"])
        return httpx.Response(503, json={"error": "local unavailable"})

    client, http = build_client(handler, max_retries=1)
    try:
        with pytest.raises(UpstreamError):
            await router(confidential(), client).complete([ChatMessage("user", "secret")])
    finally:
        await http.aclose()
    assert models == ["local-llama", "local-llama"]


def test_invalid_client_configuration() -> None:
    with pytest.raises(ValueError, match="base_url"):
        OmniRouteClient(base_url="", api_key="sk-test")
    with pytest.raises(ValueError, match="api_key"):
        OmniRouteClient(base_url="http://omniroute:20128", api_key="")
    with pytest.raises(ValueError, match="max_retries"):
        OmniRouteClient(base_url="http://omniroute:20128", api_key="sk-test", max_retries=-1)


class FakeClock:
    """A monotonic clock the test moves by hand; no test waits on real time."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class GatedTransport(httpx.AsyncBaseTransport):
    """Holds every request until the test releases it."""

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.entered = asyncio.Event()
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.entered.set()
        await self.release.wait()
        return httpx.Response(
            200, json=completion_payload(model=json.loads(request.content)["model"])
        )


async def test_a_hung_upstream_stops_at_the_request_deadline() -> None:
    """ADR-004 decision 4: one attempt ends at the budget, not timeout x attempts."""
    clock = FakeClock()
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        clock.now += 200.0  # the hung attempt consumed more than the whole budget
        raise httpx.ReadTimeout("hung upstream", request=request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OmniRouteClient(
        base_url="http://omniroute:20128",
        api_key="sk-test",
        timeout_seconds=120.0,
        max_retries=3,
        retry_backoff_seconds=0.25,
        clock=clock,
        client=http,
    )
    deadline = RequestDeadline(5.0, clock=clock)
    try:
        with pytest.raises(UpstreamTimeoutError) as info:
            await client.chat_completion(
                [ChatMessage("user", "hi")], model="cloud-primary", deadline=deadline
            )
    finally:
        await http.aclose()
    assert calls["n"] == 1
    assert info.value.http_status == 504


async def test_little_time_left_makes_zero_retries() -> None:
    clock = FakeClock()
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, json={"error": "busy"})

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OmniRouteClient(
        base_url="http://omniroute:20128",
        api_key="sk-test",
        max_retries=3,
        retry_backoff_seconds=0.25,
        clock=clock,
        client=http,
    )
    # The budget is smaller than the first backoff, so no retry can fit.
    deadline = RequestDeadline(0.1, clock=clock)
    try:
        with pytest.raises(UpstreamError) as info:
            await client.chat_completion(
                [ChatMessage("user", "hi")], model="cloud-primary", deadline=deadline
            )
    finally:
        await http.aclose()
    assert calls["n"] == 1
    assert info.value.status_code == 503


async def test_a_full_bulkhead_refuses_the_next_call_and_routes_count_apart() -> None:
    transport = GatedTransport()
    http = httpx.AsyncClient(transport=transport)
    client = OmniRouteClient(
        base_url="http://omniroute:20128",
        api_key="sk-test",
        max_concurrency=1,
        client=http,
    )
    held = asyncio.create_task(
        client.chat_completion([ChatMessage("user", "hi")], model="local-llama")
    )
    await transport.entered.wait()

    try:
        with pytest.raises(RouteBusyError):
            await client.chat_completion([ChatMessage("user", "hi")], model="local-llama")

        transport.entered.clear()
        cloud = asyncio.create_task(
            client.chat_completion([ChatMessage("user", "hi")], model="cloud-primary")
        )
        await transport.entered.wait()
    finally:
        transport.release.set()
    assert (await held).model == "local-llama"
    assert (await cloud).model == "cloud-primary"
    await http.aclose()


async def test_the_breaker_opens_half_opens_and_closes() -> None:
    clock = FakeClock()
    status = {"code": 503}
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if status["code"] >= 400:
            return httpx.Response(status["code"], json={"error": "busy"})
        return httpx.Response(200, json=completion_payload())

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OmniRouteClient(
        base_url="http://omniroute:20128",
        api_key="sk-test",
        max_retries=0,
        breaker_failure_threshold=2,
        breaker_cooldown_seconds=30.0,
        clock=clock,
        client=http,
    )
    try:
        for _ in range(2):
            with pytest.raises(UpstreamError):
                await client.chat_completion([ChatMessage("user", "hi")], model="cloud-primary")
        assert calls["n"] == 2

        # Open: refused before the wire, and the upstream sees nothing.
        with pytest.raises(BreakerOpenError):
            await client.chat_completion([ChatMessage("user", "hi")], model="cloud-primary")
        assert calls["n"] == 2

        # Half-open: exactly one probe after the cooldown, and its success closes.
        clock.now += 30.0
        status["code"] = 200
        completion = await client.chat_completion(
            [ChatMessage("user", "hi")], model="cloud-primary"
        )
        assert completion.content == "hello"
        assert calls["n"] == 3

        status["code"] = 200
        await client.chat_completion([ChatMessage("user", "hi")], model="cloud-primary")
        assert calls["n"] == 4
    finally:
        await http.aclose()


def test_invalid_availability_configuration() -> None:
    with pytest.raises(ValueError, match="max_concurrency"):
        OmniRouteClient(base_url="http://omniroute:20128", api_key="sk-test", max_concurrency=0)
    with pytest.raises(ValueError, match="breaker_failure_threshold"):
        OmniRouteClient(
            base_url="http://omniroute:20128", api_key="sk-test", breaker_failure_threshold=0
        )
    with pytest.raises(ValueError, match="breaker_cooldown_seconds"):
        OmniRouteClient(
            base_url="http://omniroute:20128", api_key="sk-test", breaker_cooldown_seconds=-1
        )
