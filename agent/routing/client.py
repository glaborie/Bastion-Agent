"""OpenAI-compatible OmniRoute client and confidentiality-aware routing.

The agent never talks to a provider directly: every completion goes through
OmniRoute's ``/v1/chat/completions`` with a model alias. ``ModelRouter`` maps a
CONFIDENTIAL classification to the local alias and PUBLIC traffic to one of two
cloud tiers, chosen by how much work the prompt is. There is no automatic cloud
fallback for confidential prompts — the local path fails closed (ADR-004).
"""

from __future__ import annotations

import asyncio
import functools
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

import httpx

from agent.routing.classifier import (
    Classification,
    SensitivityClassifier,
    get_classifier,
)
from agent.routing.complexity import Complexity, ComplexityTier, assess_complexity
from settings import get_settings
from telemetry import instrument_http_client

logger = logging.getLogger(__name__)

ChatRole = Literal["system", "user", "assistant", "tool"]
_RETRYABLE_STATUS: Final[frozenset[int]] = frozenset({408, 429, 500, 502, 503, 504})


class RoutingError(RuntimeError):
    """Base class for routing/upstream failures.

    ``http_status``/``http_detail`` are the gateway's default refusal for the
    failure; the chat boundary uses them so every routing failure maps once.
    """

    http_status: int = 502
    http_detail: str = "upstream model unavailable"


class UpstreamError(RoutingError):
    """OmniRoute returned a non-success response."""

    def __init__(self, status_code: int, code: str) -> None:
        super().__init__(f"OmniRoute returned {status_code} ({code})")
        self.status_code = status_code
        self.code = code


class UpstreamTimeoutError(RoutingError):
    """OmniRoute could not be reached before the deadline."""

    http_status = 504
    http_detail = "upstream model timed out"


class UpstreamResponseError(RoutingError):
    """OmniRoute returned a response the agent cannot interpret."""


class DeadlineExceededError(RoutingError):
    """The turn's request budget was exhausted before this stage."""

    http_status = 504
    http_detail = "request deadline exceeded"


class RouteBusyError(RoutingError):
    """The route's bulkhead is full; the call is refused instead of queued."""

    http_status = 503
    http_detail = "route temporarily unavailable"


class BreakerOpenError(RoutingError):
    """The route's availability breaker is open; the call fails fast."""

    http_status = 503
    http_detail = "route temporarily unavailable"


class RequestDeadline:
    """A wall-clock budget for one turn, shared by every stage and retry."""

    def __init__(self, seconds: float, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._expires_at = clock() + max(0.0, seconds)

    def remaining(self) -> float:
        return max(0.0, self._expires_at - self._clock())

    def check(self, stage: str) -> None:
        if self.remaining() <= 0:
            raise DeadlineExceededError(f"request deadline exceeded before {stage}")


@dataclass
class _RouteState:
    failures: int = 0
    opened_at: float | None = None
    probing: bool = False


@dataclass(frozen=True, slots=True)
class _Ticket:
    route: str
    probe: bool


class _RouteGate:
    """Per-alias concurrency limit and availability breaker (ADR-004 decision 4).

    The bulkhead bounds how many calls one alias may have in flight; the
    breaker refuses a route that keeps timing out. Both are keyed by alias, so
    a stalled local route cannot consume the cloud budget or vice versa, and
    neither can move a prompt to another alias.
    """

    def __init__(
        self,
        *,
        limit: int,
        failure_threshold: int,
        cooldown_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = limit
        self._threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._clock = clock
        self._in_flight: dict[str, int] = {}
        self._states: dict[str, _RouteState] = {}

    def _state(self, route: str) -> _RouteState:
        return self._states.setdefault(route, _RouteState())

    def acquire(self, route: str) -> _Ticket:
        """Take a slot on ``route`` or refuse immediately."""
        state = self._state(route)
        probe = False
        if state.opened_at is not None:
            if state.probing or self._clock() - state.opened_at < self._cooldown:
                raise BreakerOpenError(f"route {route} is unavailable (breaker open)")
            state.probing = True
            probe = True
        if self._in_flight.get(route, 0) >= self._limit:
            if probe:
                state.probing = False
            raise RouteBusyError(f"route {route} is at its concurrency limit")
        self._in_flight[route] = self._in_flight.get(route, 0) + 1
        return _Ticket(route, probe)

    def release(self, ticket: _Ticket, *, failed: bool | None) -> None:
        """Free the slot and feed the breaker: True=timeout/5xx, None=neutral."""
        route = ticket.route
        remaining = self._in_flight.get(route, 1) - 1
        if remaining > 0:
            self._in_flight[route] = remaining
        else:
            self._in_flight.pop(route, None)
        state = self._state(route)
        if failed is True:
            state.failures += 1
            if ticket.probe or (state.opened_at is None and state.failures >= self._threshold):
                state.opened_at = self._clock()
            state.probing = False
        elif failed is False:
            state.failures = 0
            state.opened_at = None
            state.probing = False
        elif ticket.probe:
            state.probing = False


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
    #: Set when a deterministic control moved the request off the classifier's
    #: verdict. ``"pii_detected"`` means the DLP stage found personal data and
    #: the prompt is kept on the local model regardless of the PUBLIC label.
    override: str | None = None
    #: How much work the prompt is (ADR-004 decision 3). It only chooses between
    #: cloud tiers: when ``local`` is set it is recorded and otherwise ignored.
    complexity: Complexity | None = None


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
        max_concurrency: int = 2,
        breaker_failure_threshold: int = 3,
        breaker_cooldown_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not base_url.strip():
            raise ValueError("OmniRoute base_url must not be empty")
        if not api_key:
            raise ValueError("OmniRoute api_key must not be empty")
        if max_retries < 0:
            raise ValueError("max_retries must be zero or positive")
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be at least one")
        if breaker_failure_threshold < 1:
            raise ValueError("breaker_failure_threshold must be at least one")
        if breaker_cooldown_seconds < 0:
            raise ValueError("breaker_cooldown_seconds must be zero or positive")
        self._endpoint = f"{base_url.rstrip('/')}/v1/chat/completions"
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._backoff = max(0.0, retry_backoff_seconds)
        self._gate = _RouteGate(
            limit=max_concurrency,
            failure_threshold=breaker_failure_threshold,
            cooldown_seconds=breaker_cooldown_seconds,
            clock=clock,
        )
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None
        # The wire-level model call becomes a child of the ``chat <alias>``
        # span, which is what makes retries and upstream latency visible
        # separately from the application span around them.
        instrument_http_client(self._client)

    async def chat_completion(
        self,
        messages: Sequence[ChatMessage],
        *,
        model: str,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        deadline: RequestDeadline | None = None,
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
        for attempt in range(self._max_retries + 1):
            remaining = deadline.remaining() if deadline is not None else None
            if remaining is not None and remaining <= 0:
                raise UpstreamTimeoutError("request deadline exceeded before the model call")
            started = time.monotonic()
            try:
                response = await self._post_once(model, payload, headers, remaining)
            except UpstreamTimeoutError as exc:
                if attempt < self._max_retries and self._retry_fits(deadline, attempt):
                    await self._sleep(attempt)
                    continue
                logger.warning(
                    "OmniRoute timeout",
                    extra={"model": model, "attempts": attempt + 1},
                )
                raise exc

            duration_ms = round((time.monotonic() - started) * 1000, 1)
            if (
                response.status_code in _RETRYABLE_STATUS
                and attempt < self._max_retries
                and self._retry_fits(deadline, attempt)
            ):
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

        raise RoutingError("OmniRoute request failed")

    async def _post_once(
        self,
        model: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        remaining: float | None,
    ) -> httpx.Response:
        """One attempt through the route gate, with the budget as its timeout."""
        ticket = self._gate.acquire(model)
        failed: bool | None = None
        try:
            timeout = self._timeout if remaining is None else min(self._timeout, remaining)
            try:
                response = await self._client.post(
                    self._endpoint,
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                )
            except httpx.TimeoutException as exc:
                failed = True
                raise UpstreamTimeoutError("OmniRoute request timed out") from exc
            except httpx.TransportError as exc:
                failed = True
                raise UpstreamTimeoutError("OmniRoute is unreachable") from exc
            # Only an availability failure feeds the breaker: a 4xx says the
            # route is healthy and answered, and resets the consecutive count.
            failed = response.status_code == 408 or response.status_code >= 500
            return response
        finally:
            self._gate.release(ticket, failed=failed)

    def _retry_fits(self, deadline: RequestDeadline | None, attempt: int) -> bool:
        """A retry needs its backoff inside the budget, or it makes no sense."""
        if deadline is None:
            return True
        return bool(deadline.remaining() > self._backoff * (2**attempt))

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
        self._strong_alias = settings.model_cloud_strong_alias
        self._strong_primary = settings.model_cloud_strong_primary

    @property
    def client(self) -> OmniRouteClient:
        return self._client

    def route(self, prompt: str, *, pii_detected: bool = False) -> RouteDecision:
        """Synchronous routing decision (rule/ONNX inference is cheap)."""
        return self._decision(
            self._classifier.classify(prompt),
            pii_detected=pii_detected,
            complexity=assess_complexity(prompt),
        )

    async def aroute(self, prompt: str, *, pii_detected: bool = False) -> RouteDecision:
        """Async routing decision for callers on the event loop."""
        return self._decision(
            await self._classifier.aclassify(prompt),
            pii_detected=pii_detected,
            complexity=assess_complexity(prompt),
        )

    async def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        decision: RouteDecision | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        deadline: RequestDeadline | None = None,
    ) -> ChatCompletion:
        """Complete a conversation, classifying the last user turn if needed."""
        if decision is None:
            decision = await self.aroute(_last_user_content(messages))
        return await self._client.chat_completion(
            messages,
            model=decision.alias,
            temperature=temperature,
            max_tokens=max_tokens,
            deadline=deadline,
        )

    def _decision(
        self,
        classification: Classification,
        *,
        pii_detected: bool = False,
        complexity: Complexity | None = None,
    ) -> RouteDecision:
        """Map a classification to an alias, letting a DLP hit force local.

        The classifier's label is never rewritten: the ledger keeps the
        ``PUBLIC`` verdict next to the ``pii_detected`` override, so the reason a
        prompt stayed on-box is legible after the fact. Only a route that the
        evidence did not already send local is marked as an override.

        Complexity is subordinate: it picks the strong cloud alias for a PUBLIC
        prompt that reads as hard work, and is ignored for every local route, so
        it can never move a confidential or PII-bearing prompt off the host.
        """
        confidential = classification.is_confidential
        local = confidential or pii_detected
        override = "pii_detected" if pii_detected and not confidential else None
        strong = (
            not local and complexity is not None and (complexity.tier is ComplexityTier.COMPLEX)
        )
        if local:
            alias, primary = self._local_alias, self._local_primary
        elif strong:
            alias, primary = self._strong_alias, self._strong_primary
        else:
            alias, primary = self._cloud_alias, self._cloud_primary
        return RouteDecision(
            alias=alias,
            classification=classification,
            local=local,
            primary_model=primary,
            override=override,
            complexity=complexity,
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
        max_concurrency=settings.omniroute_max_concurrency,
        breaker_failure_threshold=settings.omniroute_breaker_failure_threshold,
        breaker_cooldown_seconds=settings.omniroute_breaker_cooldown_seconds,
    )
    return ModelRouter(get_classifier(), client)


async def close_model_router() -> None:
    """Release the OmniRoute HTTP client (gateway/worker shutdown)."""
    # pylint: disable-next=too-many-function-args  # astroid misreads lru_cache
    if get_model_router.cache_info().currsize:
        await get_model_router().client.aclose()
    get_model_router.cache_clear()
    get_classifier.cache_clear()
