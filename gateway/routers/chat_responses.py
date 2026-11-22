"""OpenAPI response fragments for the native chat route (ADR-026)."""

from __future__ import annotations

from typing import Any, Final

#: The error body FastAPI emits for ``HTTPException`` here: one ``detail``
#: string, so a generated client can model the 401 instead of guessing.
_DETAIL_ERROR: Final[dict[str, Any]] = {
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "required": ["detail"],
                "properties": {"detail": {"type": "string"}},
            }
        }
    }
}

#: Every status ``run_turn`` can raise, so the document matches the runtime.
CHAT_RESPONSES: Final[dict[int | str, dict[str, Any]]] = {
    401: {"description": "Missing or invalid Bearer token", **_DETAIL_ERROR},
    403: {"description": "Session quarantined by the egress circuit breaker"},
    404: {"description": "No route or model serves the requested alias", **_DETAIL_ERROR},
    413: {"description": "Request exceeds the chat size limits"},
    422: {"description": "Unknown model alias or unsupported field"},
    429: {"description": "Request or token budget exhausted", **_DETAIL_ERROR},
    502: {"description": "Upstream failure or egress filter block"},
    503: {"description": "DLP, canary registry or quarantine store unavailable"},
    504: {"description": "Request deadline exceeded", **_DETAIL_ERROR},
}
