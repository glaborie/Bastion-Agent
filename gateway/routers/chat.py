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
6. ``SECURITY_INCIDENT`` — written when the response is blocked.

Two invariants matter more than the happy path:

* A canary leak never returns model text. The response is discarded and the
  session is quarantined; the event is audited before the error is raised.
* Vault sessions are derived from ``actor_id + conversation_id``, so a caller
  cannot pass another principal's conversation id and have their markers
  restored.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Final, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from agent.dlp.presidio import DLPUnavailableError, PresidioDLP, get_dlp
from agent.dlp.vault import VaultError
from agent.egress.sanitizer import (
    EgressCircuitOpenError,
    EgressSanitizer,
    EgressUnavailableError,
    get_egress_sanitizer,
)
from agent.routing.client import ChatMessage, ModelRouter, RoutingError, get_model_router
from db.audit import append_audit_event
from db.models import AuditEventType
from db.session import get_db_session
from gateway.auth.rbac import AuthContext, require_csrf, require_roles

logger = logging.getLogger(__name__)

router = APIRouter(tags=["chat"])

MAX_MESSAGES: Final[int] = 64
MAX_MESSAGE_CHARS: Final[int] = 32_768
MAX_TOTAL_CHARS: Final[int] = 65_536
CONVERSATION_PATTERN: Final[str] = r"^[A-Za-z0-9._:-]{1,128}$"

ChatRole = Literal["system", "user", "assistant", "tool"]


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
    max_tokens: int | None = Field(default=None, ge=1, le=8192)


class AssistantTurn(BaseModel):
    """The delivered answer. Empty is legal when the model returned nothing."""

    model_config = ConfigDict(extra="forbid")

    role: Literal["assistant"] = "assistant"
    content: str


class ChatResponse(BaseModel):
    """The sanitized answer plus the routing evidence (no canary, no markers)."""

    conversation_id: str
    message: AssistantTurn
    model: str
    route: str
    classification: str
    reason: str
    confidence: float
    restored_tokens: int = 0


def get_chat_router() -> ModelRouter:
    """Dependency seam so tests can supply a transport-level router."""
    return get_model_router()


def get_chat_dlp() -> PresidioDLP:
    """Dependency seam for the deterministic DLP stage."""
    return get_dlp()


def get_chat_sanitizer() -> EgressSanitizer:
    """Dependency seam for the egress sanitizer."""
    return get_egress_sanitizer()


def _vault_session(actor_id: str, conversation_id: str) -> str:
    """Derive a session key that cannot be chosen by another caller.

    A caller may reuse a conversation id, but the actor is bound in, so two
    principals with the same id never share vault entries or a canary.
    """
    digest = hashlib.sha256(f"{actor_id}\x00{conversation_id}".encode()).hexdigest()
    return f"chat:{digest}"


async def _record(
    session: AsyncSession,
    *,
    actor_id: str,
    event_type: AuditEventType,
    conversation_id: str,
    payload: object | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    """Append one audit record and commit it immediately.

    Each stage commits on its own so evidence survives a later upstream or
    egress failure. ``payload`` is hashed by :func:`append_audit_event`; the
    metadata dictionary must contain machine values only, never prompt text.
    """
    await append_audit_event(
        session,
        actor_id=actor_id,
        event_type=event_type,
        session_id=conversation_id,
        payload=payload,
        metadata_json=metadata or {},
    )
    await session.commit()


async def _redact_messages(
    dlp: PresidioDLP,
    messages: list[ChatTurn],
    vault_session: str,
) -> tuple[list[ChatMessage], set[str], int]:
    """Run the deterministic DLP stage over every turn."""
    redacted: list[ChatMessage] = []
    entity_types: set[str] = set()
    entity_count = 0
    for turn in messages:
        result = await dlp.redact(turn.content, vault_session)
        entity_types.update(entity.entity_type for entity in result.entities)
        entity_count += len(result.entities)
        redacted.append(ChatMessage(role=turn.role, content=result.text, name=turn.name))
    return redacted, entity_types, entity_count


def _blocked(status_code: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail=detail)


@router.post(
    "/v1/chat",
    response_model=ChatResponse,
    summary="Guarded chat completion",
    responses={
        403: {"description": "Session quarantined by the egress circuit breaker"},
        413: {"description": "Request exceeds the chat size limits"},
        502: {"description": "Upstream failure or egress filter block"},
        503: {"description": "DLP, canary registry or quarantine store unavailable"},
    },
)
async def chat(
    request: ChatRequest,
    context: AuthContext = Depends(require_roles("operator", "analyst", "admin")),
    _csrf: AuthContext = Depends(require_csrf),
    session: AsyncSession = Depends(get_db_session),
    model_router: ModelRouter = Depends(get_chat_router),
    dlp: PresidioDLP = Depends(get_chat_dlp),
    sanitizer: EgressSanitizer = Depends(get_chat_sanitizer),
) -> ChatResponse:
    """Run one guarded turn from ingress to sanitized egress."""
    actor_id = context.actor_id
    conversation_id = request.conversation_id or uuid.uuid4().hex
    vault_session = _vault_session(actor_id, conversation_id)

    total_chars = sum(len(turn.content) for turn in request.messages)
    if total_chars > MAX_TOTAL_CHARS:
        raise _blocked(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"conversation exceeds {MAX_TOTAL_CHARS} characters",
        )

    await _record(
        session,
        actor_id=actor_id,
        event_type=AuditEventType.INPUT_RECEIVED,
        conversation_id=conversation_id,
        payload=[turn.model_dump(exclude_none=True) for turn in request.messages],
        metadata={
            "conversation_id": conversation_id,
            "messages": len(request.messages),
            "roles": sorted({turn.role for turn in request.messages}),
            "chars": total_chars,
        },
    )

    # -- stage 1: deterministic DLP ---------------------------------------
    try:
        redacted, entity_types, entity_count = await _redact_messages(
            dlp, request.messages, vault_session
        )
    except (DLPUnavailableError, VaultError) as exc:
        logger.error("DLP stage failed", extra={"error": type(exc).__name__})
        raise _blocked(status.HTTP_503_SERVICE_UNAVAILABLE, "DLP stage unavailable") from exc
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # Presidio/spaCy can fail in ways that are not worth enumerating. The
        # only safe response is to stop: forwarding the unredacted text would
        # defeat the entire stage.
        logger.error("DLP stage failed", extra={"error": type(exc).__name__})
        raise _blocked(status.HTTP_503_SERVICE_UNAVAILABLE, "DLP stage unavailable") from exc

    await _record(
        session,
        actor_id=actor_id,
        event_type=AuditEventType.DLP_REDACTION,
        conversation_id=conversation_id,
        metadata={
            "redacted": entity_count > 0,
            "entities": entity_count,
            "types": sorted(entity_types),
        },
    )

    # -- stage 2: classify the raw text and route -------------------------
    # Never prefix role tags here: "[user] …" reads as a role-injection marker
    # to the guard and produced a measured false positive on a benign question.
    raw_scan = "\n\n".join(turn.content for turn in request.messages)
    decision = await model_router.aroute(raw_scan)
    classification = decision.classification
    await _record(
        session,
        actor_id=actor_id,
        event_type=AuditEventType.ROUTING_DECISION,
        conversation_id=conversation_id,
        metadata={
            "route": decision.alias,
            "local": decision.local,
            "label": classification.label.value,
            "reason": classification.reason,
            "confidence": round(classification.confidence, 4),
            "model": classification.model,
        },
    )

    # -- stage 3: canary + untrusted fences -------------------------------
    try:
        await sanitizer.ensure_available(vault_session)
        canary = await sanitizer.canary_for(vault_session)
    except EgressCircuitOpenError as exc:
        await _record(
            session,
            actor_id=actor_id,
            event_type=AuditEventType.EGRESS_FILTERED,
            conversation_id=conversation_id,
            metadata={"blocked": True, "reason": "circuit_open"},
        )
        await _record(
            session,
            actor_id=actor_id,
            event_type=AuditEventType.SECURITY_INCIDENT,
            conversation_id=conversation_id,
            metadata={"reason": "circuit_open", "stage": "preflight"},
        )
        raise _blocked(
            status.HTTP_403_FORBIDDEN,
            "session quarantined by the egress circuit breaker",
        ) from exc
    except EgressUnavailableError as exc:
        raise _blocked(status.HTTP_503_SERVICE_UNAVAILABLE, "egress sanitizer unavailable") from exc

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

    try:
        completion = await model_router.complete(
            upstream,
            decision=decision,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )
    except RoutingError as exc:
        logger.warning("Model completion failed", extra={"route": decision.alias})
        raise _blocked(status.HTTP_502_BAD_GATEWAY, "upstream model unavailable") from exc

    # -- stage 4: egress inspection ---------------------------------------
    try:
        egress = await sanitizer.inspect(completion.content, vault_session)
    except EgressUnavailableError as exc:
        raise _blocked(status.HTTP_503_SERVICE_UNAVAILABLE, "egress sanitizer unavailable") from exc

    await _record(
        session,
        actor_id=actor_id,
        event_type=AuditEventType.EGRESS_FILTERED,
        conversation_id=conversation_id,
        metadata={
            "blocked": egress.blocked,
            "reason": egress.reason,
            "restored_tokens": egress.restored_tokens,
            "unresolved_tokens": egress.unresolved_tokens,
            "model": completion.model,
            "route": decision.alias,
        },
    )

    if egress.blocked:
        await _record(
            session,
            actor_id=actor_id,
            event_type=AuditEventType.SECURITY_INCIDENT,
            conversation_id=conversation_id,
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
        raise _blocked(status.HTTP_502_BAD_GATEWAY, "egress filter blocked the model response")

    return ChatResponse(
        conversation_id=conversation_id,
        message=AssistantTurn(content=egress.text),
        model=completion.model,
        route=decision.alias,
        classification=classification.label.value,
        reason=classification.reason,
        confidence=classification.confidence,
        restored_tokens=egress.restored_tokens,
    )
