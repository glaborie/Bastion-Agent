"""OpenAI-compatible OmniRoute client and confidentiality-aware routing.

The agent never talks to a provider directly: every completion goes through
OmniRoute's ``/v1/chat/completions`` with a model alias. ``ModelRouter`` maps a
CONFIDENTIAL classification to the local alias and PUBLIC traffic to the cloud
alias. There is no automatic cloud fallback for confidential prompts — the
local path fails closed (ADR-004).
"""

from __future__ import annotations

import asyncio
import functools
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

import httpx

from agent.routing.classifier import (
    Classification,
    SensitivityClassifier,
    get_classifier,
)
from settings import get_settings

logger = logging.getLogger(__name__)

ChatRole = Literal["system", "user", "assistant", "tool"]
_RETRYABLE_STATUS: Final[frozenset[int]] = frozenset({408, 429, 500, 502, 503, 504})


class RoutingError(RuntimeError):
    """Base class for routing/upstream failures."""


class UpstreamError(RoutingError):
    """OmniRoute returned a non-success response."""

    def __init__(self, status_code: int, code: str) -> None:
        super().__init__(f"OmniRoute returned {status_code} ({code})")
        self.status_code = status_code
        self.code = code


class UpstreamTimeoutError(RoutingError):
    """OmniRoute could not be reached before the deadline."""


class UpstreamResponseError(RoutingError):
    """OmniRoute returned a response the agent cannot interpret."""


@dataclass(frozen=True, slots=True)
class ChatMessage:
    role: ChatRole
    content: str
    name: str | None = None

    def to_payload(self) -> dict[str, str]:
        payload = {"role": self.role, "content": self.content}
        if self.name:
            payload["name"] = self.name
        return payload


@dataclass(frozen=True, slots=True)
class ChatCompletion:
    content: str
    model: str
    finish_reason: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    #: USD, as reported by OmniRoute in ``usage.cost`` (None when it omits it).
    cost_usd: float | None = None
    response_id: str | None = None


@dataclass(frozen=True, slots=True)
class RouteDecision:
    """The selected alias plus the evidence that selected it."""

    alias: str
    classification: Classification
    local: bool
    #: Concrete model the alias is configured to use first (telemetry only).
    primary_model: str | None = None


class OmniRouteClient:
    """Minimal async client for OmniRoute's OpenAI-compatible chat endpoint."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout_seconds: float = 120.0,
        max_retries: int = 1,
        retry_backoff_seconds: float = 0.25,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not base_url.strip():
            raise ValueError("OmniRoute base_url must not be empty")
        if not api_key:
            raise ValueError("OmniRoute api_key must not be empty")
        if max_retries < 0:
            raise ValueError("max_retries must be zero or positive")
        self._endpoint = f"{base_url.rstrip('/')}/v1/chat/completions"
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._backoff = max(0.0, retry_backoff_seconds)
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None

    async def chat_completion(
        self,
        messages: Sequence[ChatMessage],
        *,
        model: str,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> ChatCompletion:
        """Send one non-streaming chat completion request."""
        if not messages:
            raise ValueError("at least one chat message is required")
        payload: dict[str, Any] = {
            "model": model,
            "messages": [message.to_payload() for message in messages],
            "temperature": temperature,
            "stream": False,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            started = time.monotonic()
            try:
                response = await self._client.post(
                    self._endpoint,
                    json=payload,
                    headers=headers,
                    timeout=self._timeout,
                )
            except httpx.TimeoutException as exc:
                last_error = UpstreamTimeoutError("OmniRoute request timed out")
                if attempt < self._max_retries:
                    await self._sleep(attempt)
                    continue
                logger.warning(
                    "OmniRoute timeout",
                    extra={"model": model, "attempts": attempt + 1},
                )
                raise last_error from exc
            except httpx.TransportError as exc:
                last_error = UpstreamTimeoutError("OmniRoute is unreachable")
                if attempt < self._max_retries:
                    await self._sleep(attempt)
                    continue
                logger.warning(
                    "OmniRoute transport failure",
                    extra={"model": model, "attempts": attempt + 1},
                )
                raise last_error from exc

            duration_ms = round((time.monotonic() - started) * 1000, 1)
            if response.status_code in _RETRYABLE_STATUS and attempt < self._max_retries:
                logger.warning(
                    "OmniRoute transient failure; retrying",
                    extra={
                        "model": model,
                        "status": response.status_code,
                        "attempt": attempt + 1,
                    },
                )
                await self._sleep(attempt)
                continue

            if response.status_code >= 400:
                code = _error_code(response)
                logger.warning(
                    "OmniRoute rejected the completion",
                    extra={"model": model, "status": response.status_code, "code": code},
                )
                raise UpstreamError(response.status_code, code)

            completion = _parse_completion(response, requested_model=model)
            logger.info(
                "Completion routed",
                extra={
                    "alias": model,
                    "model": completion.model,
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                    "total_tokens": completion.total_tokens,
                },
            )
            return completion

        raise last_error or RoutingError("OmniRoute request failed")

    async def _sleep(self, attempt: int) -> None:
        if self._backoff > 0:
            await asyncio.sleep(self._backoff * (2**attempt))

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class ModelRouter:
    """Classify a prompt and route it to the matching OmniRoute alias."""

    def __init__(
        self,
        classifier: SensitivityClassifier,
        client: OmniRouteClient,
        *,
        local_alias: str | None = None,
        cloud_alias: str | None = None,
    ) -> None:
        settings = get_settings()
        self._classifier = classifier
        self._client = client
        self._local_alias = local_alias or settings.model_local_alias
        self._cloud_alias = cloud_alias or settings.model_cloud_alias
        self._local_primary = settings.model_local_primary
        self._cloud_primary = settings.model_cloud_primary

    @property
    def client(self) -> OmniRouteClient:
        return self._client

    def route(self, prompt: str) -> RouteDecision:
        """Synchronous routing decision (rule/ONNX inference is cheap)."""
        return self._decision(self._classifier.classify(prompt))

    async def aroute(self, prompt: str) -> RouteDecision:
        """Async routing decision for callers on the event loop."""
        return self._decision(await self._classifier.aclassify(prompt))

    async def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        decision: RouteDecision | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> ChatCompletion:
        """Complete a conversation, classifying the last user turn if needed."""
        if decision is None:
            decision = await self.aroute(_last_user_content(messages))
        return await self._client.chat_completion(
            messages,
            model=decision.alias,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def _decision(self, classification: Classification) -> RouteDecision:
        local = classification.is_confidential
        return RouteDecision(
            alias=self._local_alias if local else self._cloud_alias,
            classification=classification,
            local=local,
            primary_model=self._local_primary if local else self._cloud_primary,
        )


def _last_user_content(messages: Sequence[ChatMessage]) -> str:
    for message in reversed(messages):
        if message.role == "user":
            return message.content
    raise RoutingError("cannot route a conversation without a user message")


def _parse_completion(response: httpx.Response, *, requested_model: str) -> ChatCompletion:
    try:
        payload = response.json()
    except ValueError as exc:
        raise UpstreamResponseError("OmniRoute response is not JSON") from exc
    if not isinstance(payload, dict):
        raise UpstreamResponseError("OmniRoute response is not an object")

    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise UpstreamResponseError("OmniRoute response has no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise UpstreamResponseError("OmniRoute choice is not an object")
    message = first.get("message")
    if not isinstance(message, dict):
        raise UpstreamResponseError("OmniRoute choice has no message")
    content = message.get("content")
    if not isinstance(content, str):
        raise UpstreamResponseError("OmniRoute message has no text content")

    usage = payload.get("usage")
    usage_dict = usage if isinstance(usage, dict) else {}
    model = payload.get("model")
    finish_reason = first.get("finish_reason")
    response_id = payload.get("id")
    return ChatCompletion(
        content=content,
        model=model if isinstance(model, str) and model else requested_model,
        finish_reason=finish_reason if isinstance(finish_reason, str) else None,
        prompt_tokens=_optional_int(usage_dict.get("prompt_tokens")),
        completion_tokens=_optional_int(usage_dict.get("completion_tokens")),
        total_tokens=_optional_int(usage_dict.get("total_tokens")),
        cost_usd=_optional_float(usage_dict.get("cost")),
        response_id=response_id if isinstance(response_id, str) else None,
    )


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _optional_float(value: object) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def _error_code(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return "http_error"
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            # Only machine-readable codes, never ``message``: upstream messages
            # may echo prompt content into logs.
            code = error.get("code") or error.get("type")
            if isinstance(code, str) and code:
                return code[:120]
    return "http_error"


@functools.lru_cache(maxsize=1)
def get_model_router() -> ModelRouter:
    """Process-wide router wired to the classifier and OmniRoute."""
    settings = get_settings()
    client = OmniRouteClient(
        base_url=settings.omniroute_base_url,
        api_key=settings.omniroute_api_key.get_secret_value(),
        timeout_seconds=settings.omniroute_timeout_seconds,
        max_retries=settings.omniroute_max_retries,
        retry_backoff_seconds=settings.omniroute_retry_backoff_seconds,
    )
    return ModelRouter(get_classifier(), client)


async def close_model_router() -> None:
    """Release the OmniRoute HTTP client (gateway/worker shutdown)."""
    # pylint: disable-next=too-many-function-args  # astroid misreads lru_cache
    if get_model_router.cache_info().currsize:
        await get_model_router().client.aclose()
    get_model_router.cache_clear()
