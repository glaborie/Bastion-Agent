"""OpenAI-compatible facade over the one guarded chat pipeline (ADR-026).

``POST /v1/chat/completions`` and ``GET /v1/models`` speak the OpenAI wire
format so an existing client can point at the gateway instead of being rewritten
as an external proxy that bypasses DLP, the canary, the injection gate and the
ledger. Every request runs through ``chat.run_turn`` — the same function the
native ``POST /v1/chat`` uses — so the guardrail path exists exactly once.

Deliberate limits, each recorded in ADR-026:

* ``model`` is a hint. The classifier's route is authoritative and the response
  reports the model that actually answered; ``bastion-local`` narrows the turn to
  the local alias, ``bastion-auto`` forces nothing, and an unknown alias is a
  ``model_not_found`` error.
* ``tools`` and ``tool_choice`` are refused: tool execution stays server-side
  behind the catalog and four-eyes, not on a caller-supplied schema.
* Client-supplied ``system`` and ``assistant`` turns are refused. ADR-012 keeps
  one gateway-written system message and lets only the model write assistant
  turns; a facade that accepted them would let a caller rewrite the guard.
* ``stream: true`` is buffered, scanned and then replayed as synthetic SSE, so
  no unscanned byte reaches the caller. True incremental streaming is a separate
  slice.
* The Responses API is out of scope.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import AsyncIterator, Mapping
from typing import Any, Final, cast

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.exception_handlers import (
    request_validation_exception_handler as default_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from agent.dlp.presidio import PresidioDLP
from agent.egress.sanitizer import EgressSanitizer
from agent.routing.client import ModelRouter
from agent.semantic_cache import SemanticCache
from db.session import get_db_session
from gateway.auth.rbac import AuthContext, require_csrf, require_roles
from gateway.auth.roles import CHAT_ROLES
from gateway.rate_limit import RateLimiter, get_rate_limiter
from gateway.routers.chat import (
    CONVERSATION_PATTERN,
    ChatRequest,
    ChatResponse,
    ChatRole,
    ChatTurn,
    get_chat_cache,
    get_chat_dlp,
    get_chat_router,
    get_chat_sanitizer,
    run_turn,
)
from settings import Settings, get_settings

router = APIRouter(tags=["openai-compat"])

#: The two names a client should ask for; everything else is a hint the
#: classifier may ignore.
ALIAS_AUTO: Final[str] = "bastion-auto"
ALIAS_LOCAL: Final[str] = "bastion-local"

#: Roles the compat surface lists in ``/v1/models``: anyone who may chat.
MODEL_ROLES: Final[tuple[str, ...]] = CHAT_ROLES

_REFUSED_MESSAGE_ROLES: Final[frozenset[str]] = frozenset({"system", "assistant"})
_COMPAT_PATHS: Final[tuple[str, ...]] = ("/v1/chat/completions", "/v1/models")

#: Every failure a compat path can answer as an OpenAI envelope: status ->
#: (documented description, ``error.type``, default ``error.code``). This table is
#: both what ``_envelope_for`` renders and what the document declares, so a
#: status one learns without the other cannot drift silently.
COMPAT_ERRORS: Final[dict[int, tuple[str, str, str]]] = {
    400: ("Malformed request", "invalid_request_error", "invalid_request"),
    401: (
        "Missing, malformed or invalid Bearer token",
        "authentication_error",
        "invalid_api_key",
    ),
    403: (
        "Authenticated, but the role may not use this endpoint",
        "permission_error",
        "forbidden",
    ),
    404: (
        "The requested model is not served by this gateway",
        "invalid_request_error",
        "model_not_found",
    ),
    413: (
        "Request exceeds the chat size limits",
        "invalid_request_error",
        "request_too_large",
    ),
    422: ("Invalid request body", "invalid_request_error", "invalid_request"),
    429: ("Request or token budget exhausted", "rate_limit_error", "rate_limit_exceeded"),
    502: ("Upstream model unavailable", "api_error", "upstream_error"),
    503: (
        "DLP, canary registry or quarantine store unavailable",
        "api_error",
        "service_unavailable",
    ),
}


class CompatMessage(BaseModel):
    """One inbound message; unknown fields are ignored, as OpenAI clients send many."""

    model_config = ConfigDict(extra="ignore")

    role: str
    content: str | None = None


class CompatRequest(BaseModel):
    """The subset of the OpenAI chat-completions body this facade honours."""

    model_config = ConfigDict(extra="ignore")

    model: str = ALIAS_AUTO
    messages: list[CompatMessage] = Field(min_length=1)
    temperature: float = 0.0
    max_tokens: int | None = None
    stream: bool = False
    tools: list[Any] | None = None
    tool_choice: Any | None = None


def openai_error(
    status_code: int,
    message: str,
    *,
    error_type: str,
    code: str,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    """The OpenAI error envelope, which clients parse instead of ``detail``."""
    return JSONResponse(
        status_code=status_code,
        content={"error": {"message": message, "type": error_type, "code": code}},
        headers=headers,
    )


def _envelope_for(exc: HTTPException) -> JSONResponse | None:
    """Translate one ``HTTPException`` raised by the pipeline into the envelope."""
    detail = exc.detail if isinstance(exc.detail, str) else "request failed"
    _description, error_type, code = COMPAT_ERRORS.get(
        exc.status_code, ("", "api_error", "internal_error")
    )
    if exc.status_code == 429 and "token budget" in detail:
        code = "token_budget_exhausted"
    if exc.status_code == 403 and "quarantin" in detail:
        code = "session_quarantined"
    return openai_error(
        exc.status_code, detail, error_type=error_type, code=code, headers=exc.headers
    )


def _is_compat_path(request: Request) -> bool:
    return request.url.path in _COMPAT_PATHS


def compat_error_response(request: Request, exc: StarletteHTTPException) -> JSONResponse | None:
    """The envelope for a compat path, or ``None`` for every other route.

    ``gateway.main`` already owns the HTTP-exception handler (login redirects,
    htmx reloads, the 429 page), so the facade hooks in there instead of
    replacing it: one handler, two shapes, decided by path.
    """
    if not _is_compat_path(request):
        return None
    return _envelope_for(
        HTTPException(status_code=exc.status_code, detail=exc.detail, headers=exc.headers)
    )


def install_error_handlers(app: Any) -> None:
    """Render body-validation errors in the OpenAI envelope on compat paths.

    HTTP errors are translated from ``gateway.main``'s existing handler through
    ``compat_error_response``; every non-compat route keeps FastAPI's shape.
    """

    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> Response:
        if not _is_compat_path(request):
            return await default_validation_exception_handler(request, exc)
        message = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        )
        return openai_error(
            422,
            message or "invalid request",
            error_type="invalid_request_error",
            code="invalid_request",
        )

    app.add_exception_handler(RequestValidationError, validation_exception_handler)


def _alias_is_local(model: str, settings: Settings) -> bool:
    """Whether ``model`` asks for the local alias; unknown names are refused."""
    known = {ALIAS_AUTO, ALIAS_LOCAL, settings.model_local_alias, settings.model_cloud_alias}
    if model not in known:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"model {model!r} is not served by this gateway; see GET /v1/models",
        )
    return model == ALIAS_LOCAL


def _to_chat_request(payload: CompatRequest) -> ChatRequest:
    """Convert the compat body, refusing what ADR-012 keeps server-side."""
    if payload.tools is not None or payload.tool_choice is not None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "tools and tool_choice are not accepted: tool execution stays "
            "server-side behind the catalog and four-eyes",
        )
    turns: list[ChatTurn] = []
    for message in payload.messages:
        if message.role in _REFUSED_MESSAGE_ROLES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                f"{message.role} messages are not accepted: the gateway writes its own "
                "system message and only the model writes assistant turns",
            )
        if message.content is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "every message needs content"
            )
        if message.role not in {"user", "tool"}:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                f"role {message.role!r} is not accepted; only user and tool turns are",
            )
        turns.append(ChatTurn(role=cast(ChatRole, message.role), content=message.content))
    return ChatRequest(
        messages=turns,
        temperature=payload.temperature,
        max_tokens=payload.max_tokens or 1024,
    )


def _completion_body(response: ChatResponse) -> dict[str, Any]:
    blocked = response.blocked
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": response.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "" if blocked else response.message.content,
                },
                "finish_reason": "content_filter" if blocked else "stop",
            }
        ],
        "bastion": {
            "conversation_id": response.conversation_id,
            "route": response.route,
            "classification": response.classification,
            "reason": response.reason,
            "confidence": response.confidence,
            "restored_tokens": response.restored_tokens,
            "blocked": blocked,
            "block_reason": response.block_reason,
        },
    }


#: The chunk object ``_synthetic_sse`` emits, declared here so the document and
#: the replay describe one stream rather than two.
_CHUNK_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "description": (
        "One `data: ` frame of the replay: a `role` delta, the whole scanned answer "
        "as one `content` delta, then an empty delta carrying `finish_reason`. The "
        "stream ends with `data: [DONE]`, which is a literal, not a JSON object."
    ),
    "properties": {
        "id": {"type": "string", "description": "One id shared by every chunk."},
        "object": {"type": "string", "enum": ["chat.completion.chunk"]},
        "created": {"type": "integer"},
        "model": {"type": "string", "description": "The model that actually answered."},
        "choices": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer"},
                    "delta": {
                        "type": "object",
                        "properties": {
                            "role": {"type": "string", "enum": ["assistant"]},
                            "content": {"type": "string"},
                        },
                    },
                    "finish_reason": {
                        "type": ["string", "null"],
                        "enum": ["stop", "content_filter"],
                    },
                },
            },
        },
    },
}

#: The non-streaming answer, field for field what ``_completion_body`` emits.
_COMPLETION_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "description": (
        "A `chat.completion` with the `bastion` extension. A policy block is still "
        "`200`: `finish_reason` is `content_filter`, `message.content` is empty and "
        "`bastion.blocked` is true — the values are the refusal signal, not model text."
    ),
    "required": ["id", "object", "created", "model", "choices", "bastion"],
    "properties": {
        "id": {"type": "string"},
        "object": {"type": "string", "enum": ["chat.completion"]},
        "created": {"type": "integer"},
        "model": {"type": "string", "description": "The model that actually answered."},
        "choices": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["index", "message", "finish_reason"],
                "properties": {
                    "index": {"type": "integer"},
                    "message": {
                        "type": "object",
                        "required": ["role", "content"],
                        "properties": {
                            "role": {"type": "string", "enum": ["assistant"]},
                            "content": {
                                "type": "string",
                                "description": "Empty when the turn is blocked.",
                            },
                        },
                    },
                    "finish_reason": {
                        "type": "string",
                        "enum": ["stop", "content_filter"],
                        "description": (
                            "`content_filter` means a policy block; the answer is not model text."
                        ),
                    },
                },
            },
        },
        "bastion": {
            "type": "object",
            "required": [
                "conversation_id",
                "route",
                "classification",
                "reason",
                "confidence",
                "restored_tokens",
                "blocked",
                "block_reason",
            ],
            "properties": {
                "conversation_id": {"type": "string"},
                "route": {"type": "string"},
                "classification": {"type": "string"},
                "reason": {"type": "string"},
                "confidence": {"type": "number"},
                "restored_tokens": {"type": "integer"},
                "blocked": {"type": "boolean"},
                "block_reason": {"type": ["string", "null"]},
            },
        },
    },
}

#: The route's two answers: a JSON completion, or the buffered SSE replay.
_COMPLETION_RESPONSE: Final[dict[str, Any]] = {
    "description": (
        "A `chat.completion` object with the `bastion` extension (conversation id, "
        "route, classification, blocked), or, when the body sets `stream: true`, a "
        "`text/event-stream` replay of that turn. The stream is buffered, not "
        "incremental: the egress scan finishes before the first byte, so a client "
        "sees no token before the whole answer is sanitized."
    ),
    "content": {
        "application/json": {"schema": _COMPLETION_SCHEMA},
        "text/event-stream": {"schema": _CHUNK_SCHEMA},
    },
}


#: The body ``openai_error`` emits, so a generated client can model a failure.
_ERROR_ENVELOPE: Final[dict[str, Any]] = {
    "type": "object",
    "required": ["error"],
    "properties": {
        "error": {
            "type": "object",
            "required": ["message", "type", "code"],
            "properties": {
                "message": {"type": "string"},
                "type": {"type": "string"},
                "code": {"type": "string"},
            },
        }
    },
}

#: The route's answers: ``200`` and every status ``COMPAT_ERRORS`` can render.
COMPAT_RESPONSES: Final[dict[int | str, dict[str, Any]]] = {
    200: _COMPLETION_RESPONSE,
    **{
        status: {
            "description": description,
            "content": {"application/json": {"schema": _ERROR_ENVELOPE}},
        }
        for status, (description, _type, _code) in COMPAT_ERRORS.items()
    },
}


def _chunk(
    *, chunk_id: str, created: int, model: str, delta: dict[str, Any], finish_reason: str | None
) -> bytes:
    payload = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
    }
    return f"data: {json.dumps(payload)}\n\n".encode()


async def _synthetic_sse(response: ChatResponse) -> AsyncIterator[bytes]:
    """Replay an already-scanned answer as SSE; nothing here is unscanned."""
    chunk_id = f"chatcmpl-{uuid.uuid4().hex}"
    created = int(time.time())
    text = "" if response.blocked else response.message.content
    yield _chunk(
        chunk_id=chunk_id,
        created=created,
        model=response.model,
        delta={"role": "assistant"},
        finish_reason=None,
    )
    if text:
        yield _chunk(
            chunk_id=chunk_id,
            created=created,
            model=response.model,
            delta={"content": text},
            finish_reason=None,
        )
    yield _chunk(
        chunk_id=chunk_id,
        created=created,
        model=response.model,
        delta={},
        finish_reason="content_filter" if response.blocked else "stop",
    )
    yield b"data: [DONE]\n\n"


def _conversation_header(value: str | None) -> str | None:
    if value is None:
        return None
    if not re.match(CONVERSATION_PATTERN, value):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"X-Bastion-Conversation-Id must match {CONVERSATION_PATTERN}",
        )
    return value


def _ephemeral_egress_session(context: AuthContext) -> str:
    """Actor-stable key for canary and quarantine when there is no conversation.

    The vault session stays per request (markers are minted and restored within
    one turn); the canary and the trip are keyed here so a leaked canary
    quarantines the principal, not a throwaway session (ADR-026).
    """
    return f"ephemeral:{context.tenant_id}\x00{context.actor_id}"


@router.get("/v1/models")
async def list_models(
    context: AuthContext = Depends(require_roles(MODEL_ROLES)),
    _csrf: AuthContext = Depends(require_csrf),
) -> dict[str, Any]:
    """The aliases this caller may ask for, in the OpenAI list shape."""
    settings = get_settings()
    created = int(time.time())
    return {
        "object": "list",
        "data": [
            {"id": alias, "object": "model", "created": created, "owned_by": "bastion"}
            for alias in (
                ALIAS_AUTO,
                ALIAS_LOCAL,
                settings.model_local_alias,
                settings.model_cloud_alias,
            )
        ],
    }


@router.post("/v1/chat/completions", responses=COMPAT_RESPONSES)
async def chat_completions(
    payload: CompatRequest,
    x_bastion_conversation_id: str | None = Header(default=None, alias="X-Bastion-Conversation-Id"),
    context: AuthContext = Depends(require_roles(CHAT_ROLES)),
    _csrf: AuthContext = Depends(require_csrf),
    session: AsyncSession = Depends(get_db_session),
    model_router: ModelRouter = Depends(get_chat_router),
    dlp: PresidioDLP = Depends(get_chat_dlp),
    sanitizer: EgressSanitizer = Depends(get_chat_sanitizer),
    cache: SemanticCache | None = Depends(get_chat_cache),
    limiter: RateLimiter = Depends(get_rate_limiter),
) -> Response:
    """Run one guarded turn and answer in the OpenAI wire format."""
    header_conversation = _conversation_header(x_bastion_conversation_id)
    force_local = _alias_is_local(payload.model, get_settings())
    chat_request = _to_chat_request(payload)

    result = await run_turn(
        chat_request,
        context=context,
        session=session,
        model_router=model_router,
        dlp=dlp,
        sanitizer=sanitizer,
        cache=cache,
        limiter=limiter,
        conversation_id=header_conversation,
        egress_session=(
            _ephemeral_egress_session(context) if header_conversation is None else None
        ),
        force_local=force_local,
    )
    headers = {"X-Bastion-Conversation-Id": result.conversation_id}
    if payload.stream:
        return StreamingResponse(
            _synthetic_sse(result), media_type="text/event-stream", headers=headers
        )
    return JSONResponse(content=_completion_body(result), headers=headers)
