"""Protected chat endpoint: the full guarded request lifecycle.

``POST /v1/chat`` is the only path that reaches a model, and every stage is
audited before the next one runs (HANDOVER_SPEC §3.4/§3.5):

1. ``INPUT_RECEIVED`` — only a canonical hash of the request is stored.
2. ``DLP_REDACTION`` — Presidio replaces identifiers with vault markers.
3. ``ROUTING_DECISION`` — the **raw** text is classified so PII cannot weaken
   the verdict; a confidential or injected prompt never reaches the cloud.
4. Egress construction — a session canary is injected into the system
   instructions and tool output is fenced as untrusted data.
5. ``EGRESS_FILTERED`` — canary leak, quarantine state and marker restore.
6. ``RESPONSE_SENT`` — the sanitized text actually delivered, hashed and (with
   the pre-production flag) escrowed as ``egress_delivered``. A turn blocked by
   the injection gate or the canary never reaches this stage.
7. ``SECURITY_INCIDENT`` — written when the response is blocked.

Two invariants matter more than the happy path:

* A canary leak never returns model text. The response is discarded and the
  session is quarantined; the event is audited before the error is raised.
* A prompt the injection guard flags is refused before the model is called, so
  no model answer exists to fabricate a system prompt from. The caller receives
  a fixed gateway notice with ``blocked=true`` and the ledger records the
  incident; the notice must not be resent as an assistant turn.
* Vault sessions are derived from ``actor_id + conversation_id``, so a caller
  cannot pass another principal's conversation id and have their markers
  restored.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, replace
from typing import Final, Literal, TypedDict

from fastapi import APIRouter, Depends, HTTPException, status
from opentelemetry import trace
from opentelemetry.trace import SpanKind
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from agent.dlp.presidio import PresidioDLP, get_dlp
from agent.egress.sanitizer import (
    EgressCircuitOpenError,
    EgressResult,
    EgressSanitizer,
    EgressUnavailableError,
    get_egress_sanitizer,
)
from agent.routing.client import (
    ChatCompletion,
    ChatMessage,
    DeadlineExceededError,
    ModelRouter,
    RequestDeadline,
    RouteDecision,
    RoutingError,
    get_model_router,
)
from agent.semantic_cache import SemanticCache, TokenSimilarity
from agent.sentiment import assess as assess_frustration
from db.audit import append_audit_event
from db.models import AuditEventType, EscrowKind
from db.redis import get_redis
from db.session import get_db_session
from gateway.auth.rbac import AuthContext, require_csrf, require_roles
from gateway.auth.roles import CHAT_ROLES
from gateway.rate_limit import (
    RateLimiter,
    RateLimitUnavailable,
    estimate_prompt_tokens,
    get_rate_limiter,
    rate_limit,
    refusal_headers,
    settled_tokens,
)
from gateway.routers.chat_tracing import completion_attributes, split_model
from settings import Settings, get_settings
from telemetry import annotate_span, span_attributes

logger = logging.getLogger(__name__)

#: Resolves to the provider's tracer once ``configure_tracing`` runs; the proxy
#: is safe to grab at import time.
_tracer = trace.get_tracer(__name__)

#: Local names keep the guardrail call sites readable; the helpers live in
#: ``telemetry`` so the ARQ worker annotates its spans the same way.
_attributes = span_attributes
_annotate = annotate_span

router = APIRouter(
    tags=["chat"],
    dependencies=[Depends(rate_limit("chat"))],
)

MAX_MESSAGES: Final[int] = 64
MAX_MESSAGE_CHARS: Final[int] = 32_768
MAX_TOTAL_CHARS: Final[int] = 65_536
CONVERSATION_PATTERN: Final[str] = r"^[A-Za-z0-9._:-]{1,128}$"

#: Only caller-authored turns. The gateway writes the one system message and
#: the model alone writes assistant turns, so neither is accepted here
#: (ADR-012 section 3). ``tool`` stays because tool output is fenced as data.
ChatRole = Literal["user", "tool"]

#: Reason the classifier sets when the injection guard fires (ADR-011).
_INJECTION_REASON: Final[str] = "prompt_injection_detected"
#: What the caller receives instead of a model answer on a detected injection.
#: Worded as a gateway verdict, not as model output: the model was never called.
_INJECTION_NOTICE: Final[str] = (
    "Request blocked: prompt injection detected. No model answer was released, "
    "so no fabricated system prompt can be delivered."
)


class ChatTurn(BaseModel):
    """One inbound message. ``extra="forbid"`` keeps unknown fields out."""

    model_config = ConfigDict(extra="forbid")

    role: ChatRole
    content: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)
    name: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")


class ChatRequest(BaseModel):
    """A single non-streaming completion request."""

    model_config = ConfigDict(extra="forbid")

    messages: list[ChatTurn] = Field(min_length=1, max_length=MAX_MESSAGES)
    #: Stable across turns. Omit it on the first call and reuse the value in
    #: the response; it scopes the token vault and the canary to this thread.
    conversation_id: str | None = Field(default=None, pattern=CONVERSATION_PATTERN)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    #: Always sent upstream: a reservation computed against a provider-side
    #: default could not be reconstructed, and that default can change under
    #: the gate (ADR-020 decision 3).
    max_tokens: int = Field(default=1024, ge=1, le=8192)


class AssistantTurn(BaseModel):
    """The delivered answer. Empty is legal when the model returned nothing."""

    model_config = ConfigDict(extra="forbid")

    role: Literal["assistant"] = "assistant"
    content: str


class ChatResponse(BaseModel):
    """The sanitized answer plus the routing evidence (no canary, no markers).

    ``blocked`` is set when a control withheld the model answer. Today that is
    the injection gate: the model is not called, so ``message`` is a fixed
    gateway notice and ``model`` is ``gateway``, not a provider. Callers must
    not resend a blocked notice as an assistant turn.
    """

    conversation_id: str
    message: AssistantTurn
    model: str
    route: str
    classification: str
    reason: str
    confidence: float
    restored_tokens: int = 0
    blocked: bool = False
    block_reason: str | None = None


def get_chat_router() -> ModelRouter:
    """Dependency seam so tests can supply a transport-level router."""
    return get_model_router()


def get_chat_dlp() -> PresidioDLP:
    """Dependency seam for the deterministic DLP stage."""
    return get_dlp()


def get_chat_sanitizer() -> EgressSanitizer:
    """Dependency seam for the egress sanitizer."""
    return get_egress_sanitizer()


def get_chat_cache() -> SemanticCache | None:
    """Dependency seam for the completion cache; ``None`` when it is off."""
    settings = get_settings()
    if not settings.semantic_cache_enabled:
        return None
    return SemanticCache(
        get_redis(settings.redis_url, max_connections=settings.redis_max_connections),
        backend=TokenSimilarity(),
        threshold=settings.semantic_cache_similarity_threshold,
        ttl_seconds=settings.semantic_cache_ttl_seconds,
        max_entries=settings.semantic_cache_max_entries,
    )


def _vault_session(tenant_id: str, actor_id: str, conversation_id: str) -> str:
    """Derive a session key that cannot be chosen by another caller.

    A caller may reuse a conversation id, but the tenant and actor are bound in,
    so two principals (or two tenants) with the same id never share vault entries
    or a canary (ADR-015).
    """
    digest = hashlib.sha256(f"{tenant_id}\x00{actor_id}\x00{conversation_id}".encode()).hexdigest()
    return f"chat:{digest}"


async def _record(
    state: _Turn,
    *,
    event_type: AuditEventType,
    payload: object | None = None,
    metadata: dict[str, object] | None = None,
    escrow: bool = False,
    escrow_kind: EscrowKind = EscrowKind.INPUT_RAW,
) -> None:
    """Append one audit record and commit it immediately.

    Each stage commits on its own so evidence survives a later upstream or
    egress failure. ``payload`` is hashed by :func:`append_audit_event`; the
    metadata dictionary must contain machine values only, never prompt text.
    ``escrow=True`` (pre-production only) also writes the encrypted payload copy
    for the same record, in the same transaction, under ``escrow_kind``.
    """
    await append_audit_event(
        state.session,
        **state.audit_actor,
        event_type=event_type,
        session_id=state.conversation_id,
        payload=payload,
        metadata_json=metadata or {},
        escrow=escrow,
        escrow_kind=escrow_kind,
    )
    await state.session.commit()


async def _redact_messages(
    dlp: PresidioDLP,
    messages: list[ChatTurn],
    tenant_id: str,
    vault_session: str,
) -> tuple[list[ChatMessage], set[str], int]:
    """Run the deterministic DLP stage over the conversation and every turn.

    An identifier split across two adjacent turns matches neither half, so the
    conversation is analysed as one text (no separator) for detection, entity
    types and the ``pii_detected`` decision (ADR-002). The per-turn pass still
    produces the redacted outbound payload. Tokens are stable per session, so a
    value found by both passes is counted once.
    """
    conversation = await dlp.redact(
        "".join(turn.content for turn in messages), vault_session, tenant_id=tenant_id
    )
    tokens = {entity.token for entity in conversation.entities}
    entity_types = set(conversation.entity_types)

    redacted: list[ChatMessage] = []
    for turn in messages:
        result = await dlp.redact(turn.content, vault_session, tenant_id=tenant_id)
        entity_types.update(entity.entity_type for entity in result.entities)
        tokens.update(entity.token for entity in result.entities)
        redacted.append(ChatMessage(role=turn.role, content=result.text, name=turn.name))
    return redacted, entity_types, len(tokens)


class _AuditActor(TypedDict):
    actor_id: str
    tenant_id: str
    actor_type: str
    agent_id: str | None
    owner_sub: str | None


@dataclass(frozen=True, slots=True)
class _Turn:
    """The request-scoped identity every stage writes its audit row against."""

    actor_id: str
    tenant_id: str
    conversation_id: str
    vault_session: str
    session: AsyncSession
    actor_type: str = "human"
    agent_id: str | None = None
    owner_sub: str | None = None
    rate_limit_subject: str = ""
    allowed_route_aliases: frozenset[str] | None = None
    #: Keys the canary and the quarantine. Equal to ``vault_session`` for the
    #: native endpoint; the compat facade pins it to the actor so an ephemeral
    #: conversation cannot escape a trip (ADR-026).
    egress_session: str = ""

    @property
    def audit_actor(self) -> _AuditActor:
        """The actor arguments every audit row in this turn carries."""
        return {
            "actor_id": self.actor_id,
            "tenant_id": self.tenant_id,
            "actor_type": self.actor_type,
            "agent_id": self.agent_id,
            "owner_sub": self.owner_sub,
        }

    @property
    def egress_key(self) -> str:
        """The key the canary and the quarantine use."""
        return self.egress_session or self.vault_session


def _cache_prompt(redacted: list[ChatMessage]) -> str | None:
    """The current question: the last user turn, after DLP redaction."""
    for message in reversed(redacted):
        if message.role == "user":
            return message.content
    return None


async def _ingress(state: _Turn, request: ChatRequest) -> None:
    """Stage 0: size limit, ``INPUT_RECEIVED`` and the request span attributes."""
    total_chars = sum(len(turn.content) for turn in request.messages)
    if total_chars > MAX_TOTAL_CHARS:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"conversation exceeds {MAX_TOTAL_CHARS} characters",
        )

    await _record(
        state,
        event_type=AuditEventType.INPUT_RECEIVED,
        payload=[turn.model_dump(exclude_none=True) for turn in request.messages],
        metadata={
            "conversation_id": state.conversation_id,
            "messages": len(request.messages),
            "roles": sorted({turn.role for turn in request.messages}),
            "chars": total_chars,
        },
        # The raw payload is what this row hashes, so it is the one thing an
        # investigator can check against the ledger. No-op unless the
        # pre-production escrow flag is on (ADR-005 decision 7).
        escrow=True,
    )
    _annotate(
        {
            "gen_ai.conversation.id": state.conversation_id,
            "bastion.conversation.id": state.conversation_id,
            "bastion.request.messages": len(request.messages),
            "bastion.request.chars": total_chars,
        }
    )


async def _dlp_stage(
    state: _Turn, dlp: PresidioDLP, request: ChatRequest
) -> tuple[list[ChatMessage], int]:
    """Stage 1: redact, then record ``DLP_REDACTION``."""
    try:
        redacted, entity_types, entity_count = await _redact_messages(
            dlp, request.messages, state.tenant_id, state.vault_session
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # Presidio/spaCy can fail in ways that are not worth enumerating, and a
        # vault error is no safer. The only safe response is to stop: forwarding
        # the unredacted text would defeat the entire stage.
        logger.error("DLP stage failed", extra={"error": type(exc).__name__})
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "DLP stage unavailable") from exc

    await _record(
        state,
        event_type=AuditEventType.DLP_REDACTION,
        metadata={
            "redacted": entity_count > 0,
            "entities": entity_count,
            "types": sorted(entity_types),
        },
    )
    _annotate(
        {
            "bastion.dlp.redacted": entity_count > 0,
            "bastion.dlp.entities": entity_count,
            "bastion.dlp.types": ",".join(sorted(entity_types)),
        }
    )
    return redacted, entity_count


async def _routing_stage(
    state: _Turn,
    model_router: ModelRouter,
    request: ChatRequest,
    entity_count: int,
    *,
    force_local: bool = False,
) -> RouteDecision:
    """Stage 2: classify the raw text, route, record ``ROUTING_DECISION``."""
    # Never prefix role tags here: "[user] …" reads as a role-injection marker
    # to the guard and produced a measured false positive on a benign question.
    raw_scan = "\n\n".join(turn.content for turn in request.messages)
    # A DLP hit means the stage found personal data, so its own recall on this
    # prompt is not trusted: the request stays on the local model even when the
    # classifier reads it as PUBLIC. That is the control that keeps a record
    # whose name or address Presidio missed off a third-party provider.
    try:
        decision = await model_router.aroute(raw_scan, pii_detected=entity_count > 0)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # Fail closed: without a verdict there is no dependable route, so the
        # prompt is neither sent upstream nor answered (ADR-004 decision 3).
        logger.error("Routing classifier failed", extra={"error": type(exc).__name__})
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "routing classifier unavailable"
        ) from exc
    if force_local and not decision.local:
        # A caller asking for `bastion-local` may only narrow where the prompt
        # goes, never widen it: the turn moves to the local model and the
        # routing row records why (ADR-026).
        decision = replace(
            decision,
            alias=get_settings().model_local_alias,
            local=True,
            override="client_alias_local",
            primary_model=None,
        )
    classification = decision.classification
    if (
        state.allowed_route_aliases is not None
        and decision.alias not in state.allowed_route_aliases
    ):
        # The router's choice is authoritative, so this is the only place the
        # alias allowlist cannot be bypassed by a client hint (ADR-027).
        await _record(
            state,
            event_type=AuditEventType.SECURITY_INCIDENT,
            metadata={"reason": "route_alias_not_allowed", "route": decision.alias},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "route alias not allowed for this agent")
    complexity = decision.complexity
    await _record(
        state,
        event_type=AuditEventType.ROUTING_DECISION,
        metadata={
            "route": decision.alias,
            "local": decision.local,
            "label": classification.label.value,
            "reason": classification.reason,
            "confidence": round(classification.confidence, 4),
            "model": classification.model,
            "override": decision.override,
            "complexity": complexity.tier.value if complexity else None,
            "complexity_score": round(complexity.score, 3) if complexity else None,
        },
    )
    _annotate(
        {
            "bastion.route": decision.alias,
            "bastion.route.local": decision.local,
            "bastion.route.override": decision.override,
            "bastion.classification": classification.label.value,
            "bastion.classification.reason": classification.reason,
            "bastion.classification.confidence": round(classification.confidence, 4),
            "bastion.complexity": complexity.tier.value if complexity else None,
            "bastion.complexity.score": round(complexity.score, 3) if complexity else None,
        }
    )
    return decision


async def _handoff_stage(state: _Turn, request: ChatRequest) -> None:
    """ADR-022: record a handoff when the caller's own turns read as frustrated.

    The stage observes the turn and changes nothing: the route, the canary, the
    egress verdict and the delivered answer are identical with it enabled or
    disabled. Only ``user`` turns are read, so an escalation demand inside
    fenced tool output cannot create a handoff.
    """
    if not get_settings().sentiment_detection_enabled:
        return
    verdict = assess_frustration([(turn.role, turn.content) for turn in request.messages])
    if verdict is None:
        return
    await _record(
        state,
        event_type=AuditEventType.HANDOFF_REQUIRED,
        metadata={
            "conversation_id": state.conversation_id,
            "verdict": verdict.reason,
            "markers": len(verdict.markers),
            "user_turns": verdict.user_turns,
        },
    )
    _annotate(
        {
            "bastion.handoff.required": True,
            "bastion.handoff.verdict": verdict.reason,
        }
    )


async def _preflight(state: _Turn, sanitizer: EgressSanitizer) -> str:
    """Stage 3: clear the circuit breaker and mint the session canary."""
    try:
        await sanitizer.ensure_available(state.tenant_id, state.egress_key)
        return await sanitizer.canary_for(state.tenant_id, state.egress_key)
    except EgressCircuitOpenError as exc:
        await _record(
            state,
            event_type=AuditEventType.EGRESS_FILTERED,
            metadata={"blocked": True, "reason": "circuit_open"},
        )
        await _record(
            state,
            event_type=AuditEventType.SECURITY_INCIDENT,
            metadata={"reason": "circuit_open", "stage": "preflight"},
        )
        _annotate({"bastion.egress.blocked": True, "bastion.egress.reason": "circuit_open"})
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "session quarantined by the egress circuit breaker",
        ) from exc
    except EgressUnavailableError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "egress sanitizer unavailable"
        ) from exc


async def _injection_gate(state: _Turn, decision: RouteDecision) -> ChatResponse | None:
    """Stage 3a: refuse a flagged prompt before the model is called (ADR-012)."""
    # The guard already made this CONFIDENTIAL and kept it local. Treat it as
    # hostile: refuse before inference, so no model answer exists to fabricate a
    # system prompt from, and tell the caller that the request was caught. The
    # model is deliberately not called and no RESPONSE_SENT row is written.
    classification = decision.classification
    if classification.reason != _INJECTION_REASON:
        return None

    await _record(
        state,
        event_type=AuditEventType.EGRESS_FILTERED,
        metadata={
            "blocked": True,
            "reason": "prompt_injection",
            "restored_tokens": 0,
            "unresolved_tokens": 0,
            "disclosure_claim": None,
            "model": "gateway",
            "route": decision.alias,
        },
    )
    await _record(
        state,
        event_type=AuditEventType.SECURITY_INCIDENT,
        metadata={
            "reason": _INJECTION_REASON,
            "stage": "routing",
            "route": decision.alias,
            "label": classification.label.value,
            "confidence": round(classification.confidence, 4),
        },
    )
    _annotate(
        {
            "bastion.egress.blocked": True,
            "bastion.egress.reason": "prompt_injection",
            "bastion.injection.detected": True,
        }
    )
    return ChatResponse(
        message=AssistantTurn(content=_INJECTION_NOTICE),
        model="gateway",
        route=decision.alias,
        classification=classification.label.value,
        reason=classification.reason,
        conversation_id=state.conversation_id,
        confidence=classification.confidence,
        restored_tokens=0,
        blocked=True,
        block_reason=_INJECTION_REASON,
    )


async def _complete(
    state: _Turn,
    model_router: ModelRouter,
    request: ChatRequest,
    redacted: list[ChatMessage],
    canary: str,
    decision: RouteDecision,
    sanitizer: EgressSanitizer,
    limiter: RateLimiter,
    deadline: RequestDeadline,
) -> ChatCompletion:
    """Stage 3b: build the fenced upstream payload and call the routed model."""
    upstream: list[ChatMessage] = [
        ChatMessage(role="system", content=sanitizer.with_canary("", canary))
    ]
    for message in redacted:
        content = (
            sanitizer.fence_untrusted(message.content, source=message.name or "tool")
            if message.role == "tool"
            else message.content
        )
        upstream.append(ChatMessage(role=message.role, content=content, name=message.name))

    # The LLM span carries the GenAI semantic conventions OpenLit turns into
    # token counts and cost. It is a child of the server span, so one turn is
    # still one trace. The requested model is the alias's pinned target, never
    # the alias: see _completion_attributes.
    settings = get_settings()
    # The worst case of this turn: the text actually sent plus the output cap.
    requested_tokens = estimate_prompt_tokens(upstream) + request.max_tokens
    requested_provider, requested_model = split_model(decision.primary_model or decision.alias)
    with _tracer.start_as_current_span(
        f"chat {decision.alias}", kind=SpanKind.CLIENT
    ) as model_span:
        model_span.set_attributes(
            _attributes(
                {
                    "gen_ai.operation.name": "chat",
                    "gen_ai.conversation.id": state.conversation_id,
                    "gen_ai.system": requested_provider,
                    "gen_ai.request.model": requested_model,
                    "gen_ai.request.temperature": request.temperature,
                    "gen_ai.request.max_tokens": request.max_tokens,
                    "bastion.route": decision.alias,
                }
            )
        )
        reserved = 0
        if settings.rate_limit_enabled:
            try:
                reservation = await limiter.reserve(
                    state.rate_limit_subject or state.actor_id,
                    tokens=requested_tokens,
                    capacity=settings.rate_limit_chat_tokens_per_window,
                    window_seconds=settings.rate_limit_window_seconds,
                )
            except RateLimitUnavailable as exc:
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE, "rate limiter unavailable"
                ) from exc
            model_span.set_attributes(
                _attributes(
                    {
                        "bastion.rate_limit.tokens_requested": requested_tokens,
                        "bastion.rate_limit.remaining": reservation.remaining,
                    }
                )
            )
            if not reservation.allowed:
                # Refused before dispatch: the model is not called and no
                # spend is recorded for this turn (ADR-020 decision 2).
                logger.warning(
                    "Token budget exhausted",
                    extra={
                        "subject": state.actor_id,
                        "conversation_id": state.conversation_id,
                        "tokens_requested": requested_tokens,
                        "remaining": reservation.remaining,
                        "retry_after_seconds": reservation.retry_after_seconds,
                    },
                )
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="token budget exhausted",
                    headers=refusal_headers(reservation),
                )
            reserved = requested_tokens

        try:
            completion = await model_router.complete(
                upstream,
                decision=decision,
                temperature=request.temperature,
                max_tokens=request.max_tokens,
                deadline=deadline,
            )
        except RoutingError as exc:
            model_span.set_attribute("error.type", type(exc).__name__)
            logger.warning("Model completion failed", extra={"route": decision.alias})
            if decision.override == "pii_detected":
                # The prompt was kept off the cloud because DLP found personal
                # data. Falling back would undo that control, so the request
                # fails closed and the attempt is on the ledger (ADR-004).
                await _record(
                    state,
                    event_type=AuditEventType.SECURITY_INCIDENT,
                    metadata={
                        "reason": "pii_route_local_unavailable",
                        "stage": "model",
                        "route": decision.alias,
                        "error": type(exc).__name__,
                    },
                )
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "local model unavailable for a PII-bearing prompt",
                ) from exc
            raise HTTPException(exc.http_status, exc.http_detail) from exc
        model_span.set_attributes(
            completion_attributes(completion, requested=decision.primary_model or decision.alias)
        )
        if reserved:
            # Settlement never fails the turn: the answer is already paid for
            # and a Redis blip must not turn it into a lost request (ADR-020
            # decision 6). Unknown usage is charged at the reservation.
            consumed = settled_tokens(
                prompt_tokens=completion.prompt_tokens,
                completion_tokens=completion.completion_tokens,
                total_tokens=completion.total_tokens,
            )
            try:
                remaining = await limiter.settle(
                    state.rate_limit_subject or state.actor_id,
                    delta=0 if consumed is None else consumed - reserved,
                    capacity=settings.rate_limit_chat_tokens_per_window,
                    window_seconds=settings.rate_limit_window_seconds,
                )
            except RateLimitUnavailable:
                logger.warning(
                    "Token budget settlement failed",
                    extra={"subject": state.actor_id, "tokens_reserved": reserved},
                )
                model_span.set_attribute("bastion.rate_limit.settle_failed", True)
            else:
                model_span.set_attributes(
                    _attributes(
                        {
                            "bastion.rate_limit.tokens_consumed": (
                                reserved if consumed is None else consumed
                            ),
                            "bastion.rate_limit.remaining": remaining,
                        }
                    )
                )
    return completion


async def _egress_stage(
    state: _Turn,
    sanitizer: EgressSanitizer,
    completion: ChatCompletion,
    decision: RouteDecision,
) -> EgressResult:
    """Stage 4: scan the answer, record ``EGRESS_FILTERED``, refuse a leak."""
    try:
        egress = await sanitizer.inspect(
            completion.content,
            state.vault_session,
            tenant_id=state.tenant_id,
            egress_session=state.egress_key,
        )
    except EgressUnavailableError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "egress sanitizer unavailable"
        ) from exc

    await _record(
        state,
        event_type=AuditEventType.EGRESS_FILTERED,
        metadata={
            "blocked": egress.blocked,
            "reason": egress.reason,
            "restored_tokens": egress.restored_tokens,
            "unresolved_tokens": egress.unresolved_tokens,
            "disclosure_claim": egress.disclosure_claim,
            "model": completion.model,
            "route": decision.alias,
        },
    )
    _annotate(
        {
            "bastion.egress.blocked": egress.blocked,
            "bastion.egress.reason": egress.reason,
            "bastion.egress.restored_tokens": egress.restored_tokens,
            "bastion.egress.unresolved_tokens": egress.unresolved_tokens,
            "bastion.egress.disclosure_claim": egress.disclosure_claim,
        }
    )

    if egress.blocked:
        await _record(
            state,
            event_type=AuditEventType.SECURITY_INCIDENT,
            metadata={
                "reason": egress.reason,
                "stage": "egress",
                "model": completion.model,
                "route": decision.alias,
            },
        )
        logger.error(
            "Egress filter blocked a model response",
            extra={"reason": egress.reason, "route": decision.alias},
        )
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "egress filter blocked the model response")
    return egress


async def _delivery_stage(
    state: _Turn,
    settings: Settings,
    egress: EgressResult,
    completion: ChatCompletion,
    decision: RouteDecision,
    *,
    cache_hit: bool = False,
) -> ChatResponse:
    """Stage 5: record ``RESPONSE_SENT`` for the text that is actually delivered."""
    # The payload is the sanitized text (or its configured prefix), so its
    # payload_hash covers exactly what the caller received. The escrow copy is a
    # no-op unless the pre-production flag is on. A blocked turn raised above
    # and therefore has no answer event.
    stored_answer = egress.text[: settings.response_store_max_chars]
    truncated = len(egress.text) > len(stored_answer)
    await _record(
        state,
        event_type=AuditEventType.RESPONSE_SENT,
        payload=stored_answer,
        metadata={
            "model": completion.model,
            "route": decision.alias,
            "chars": len(egress.text),
            "stored_chars": len(stored_answer),
            "truncated": truncated,
            "cache_hit": cache_hit,
        },
        escrow=True,
        escrow_kind=EscrowKind.EGRESS_DELIVERED,
    )
    _annotate(
        {
            "bastion.response.chars": len(egress.text),
            "bastion.response.truncated": truncated,
            "bastion.cache.hit": cache_hit,
        }
    )
    classification = decision.classification
    return ChatResponse(
        message=AssistantTurn(content=egress.text),
        model=completion.model,
        route=decision.alias,
        classification=classification.label.value,
        reason=classification.reason,
        conversation_id=state.conversation_id,
        confidence=classification.confidence,
        restored_tokens=egress.restored_tokens,
    )


async def run_turn(
    request: ChatRequest,
    *,
    context: AuthContext,
    session: AsyncSession,
    model_router: ModelRouter,
    dlp: PresidioDLP,
    sanitizer: EgressSanitizer,
    cache: SemanticCache | None,
    limiter: RateLimiter,
    conversation_id: str | None = None,
    egress_session: str | None = None,
    force_local: bool = False,
) -> ChatResponse:
    """The one guarded pipeline: the native endpoint and the compat facade share it.

    Extracting this is what keeps DLP, routing, the injection gate, egress and
    audit at exactly one implementation (ADR-026): a second adapter multiplies
    the call sites, never the stage order.
    """
    conversation = conversation_id or request.conversation_id or uuid.uuid4().hex
    vault_session = _vault_session(context.tenant_id, context.actor_id, conversation)
    state = _Turn(
        actor_id=context.actor_id,
        tenant_id=context.tenant_id,
        actor_type=context.actor_type,
        agent_id=context.agent_id,
        owner_sub=context.owner_sub,
        rate_limit_subject=context.rate_limit_subject,
        allowed_route_aliases=context.allowed_route_aliases,
        conversation_id=conversation,
        vault_session=vault_session,
        egress_session=egress_session or vault_session,
        session=session,
    )

    deadline = RequestDeadline(get_settings().request_deadline_seconds)
    try:
        deadline.check("ingress")
        await _ingress(state, request)
        deadline.check("dlp")
        redacted, entity_count = await _dlp_stage(state, dlp, request)
        deadline.check("routing")
        decision = await _routing_stage(
            state, model_router, request, entity_count, force_local=force_local
        )
        deadline.check("handoff")
        await _handoff_stage(state, request)
        deadline.check("preflight")
        canary = await _preflight(state, sanitizer)
        if (blocked := await _injection_gate(state, decision)) is not None:
            return blocked
        # The cache sits after DLP and routing so its scope carries the label and
        # the alias, and a turn that minted DLP markers is never looked up or
        # stored: those markers belong to this session (ADR-024).
        prompt = _cache_prompt(redacted)
        cached: str | None = None
        if cache is not None and prompt is not None and entity_count == 0:
            cached = await cache.lookup(
                tenant_id=state.tenant_id,
                alias=decision.alias,
                label=decision.classification.label.value,
                prompt=prompt,
            )
        if cached is not None:
            completion = ChatCompletion(content=cached, model="semantic-cache")
        else:
            deadline.check("model")
            completion = await _complete(
                state,
                model_router,
                request,
                redacted,
                canary,
                decision,
                sanitizer,
                limiter,
                deadline,
            )
        deadline.check("egress")
        egress = await _egress_stage(state, sanitizer, completion, decision)
        if (
            cache is not None
            and cached is None
            and prompt is not None
            and entity_count == 0
            and egress.unresolved_tokens == 0
        ):
            await cache.store(
                tenant_id=state.tenant_id,
                alias=decision.alias,
                label=decision.classification.label.value,
                prompt=prompt,
                answer=completion.content,
            )
        deadline.check("delivery")
        return await _delivery_stage(
            state,
            get_settings(),
            egress,
            completion,
            decision,
            cache_hit=cached is not None,
        )
    except DeadlineExceededError as exc:
        logger.warning("Request deadline exceeded", extra={"conversation_id": conversation})
        raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, "request deadline exceeded") from exc


@router.post(
    "/v1/chat",
    response_model=ChatResponse,
    summary="Guarded chat completion",
    responses={
        403: {"description": "Session quarantined by the egress circuit breaker"},
        413: {"description": "Request exceeds the chat size limits"},
        422: {"description": "Unknown model alias or unsupported field"},
        502: {"description": "Upstream failure or egress filter block"},
        503: {"description": "DLP, canary registry or quarantine store unavailable"},
    },
)
async def chat(
    request: ChatRequest,
    context: AuthContext = Depends(require_roles(CHAT_ROLES)),
    _csrf: AuthContext = Depends(require_csrf),
    session: AsyncSession = Depends(get_db_session),
    model_router: ModelRouter = Depends(get_chat_router),
    dlp: PresidioDLP = Depends(get_chat_dlp),
    sanitizer: EgressSanitizer = Depends(get_chat_sanitizer),
    cache: SemanticCache | None = Depends(get_chat_cache),
    limiter: RateLimiter = Depends(get_rate_limiter),
) -> ChatResponse:
    """Run one guarded turn from ingress to sanitized egress."""
    return await run_turn(
        request,
        context=context,
        session=session,
        model_router=model_router,
        dlp=dlp,
        sanitizer=sanitizer,
        cache=cache,
        limiter=limiter,
    )
