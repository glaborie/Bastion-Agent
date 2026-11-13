"""Approval-token primitives: request fingerprints and HMAC capability tokens.

Pure functions only. A token binds one four-eyes decision to the exact tool
invocation and expiry it was raised for, so a swapped argument set or a stale
ticket fails verification (ADR-005). ``db.models`` re-exports these names for
callers that import the primitive from there.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Final

from db.hashing import canonical_timestamp, hash_payload

_APPROVAL_TOKEN_VERSION: Final[str] = "v1"  # noqa: S105 - format tag, not a secret


def fingerprint_request(tool_name: str, arguments: Mapping[str, Any]) -> str:
    """Bind an approval to the *exact* tool invocation (prevents TOCTOU swaps)."""
    return hash_payload({"tool": tool_name, "arguments": dict(arguments)})


def _approval_token_message(
    *, ticket_id: uuid.UUID | str, request_fingerprint: str, expires_at: datetime
) -> bytes:
    return "|".join(
        (
            _APPROVAL_TOKEN_VERSION,
            str(ticket_id),
            request_fingerprint,
            canonical_timestamp(expires_at),
        )
    ).encode("utf-8")


def sign_approval_token(
    *,
    ticket_id: uuid.UUID | str,
    request_fingerprint: str,
    expires_at: datetime,
    secret: str,
) -> str:
    """Produce an HMAC-SHA256 capability token for one specific approval ticket."""
    if not secret:
        raise ValueError("approval HMAC secret must not be empty")
    digest = hmac.new(
        secret.encode("utf-8"),
        _approval_token_message(
            ticket_id=ticket_id,
            request_fingerprint=request_fingerprint,
            expires_at=expires_at,
        ),
        hashlib.sha256,
    ).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{_APPROVAL_TOKEN_VERSION}.{encoded}"


def hash_approval_token(token: str) -> str:
    """Hash a token for at-rest storage; the plaintext token is never persisted."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_approval_token(
    *,
    token: str,
    ticket_id: uuid.UUID | str,
    request_fingerprint: str,
    expires_at: datetime,
    secret: str,
) -> bool:
    """Constant-time verification of a presented approval token."""
    expected = sign_approval_token(
        ticket_id=ticket_id,
        request_fingerprint=request_fingerprint,
        expires_at=expires_at,
        secret=secret,
    )
    return hmac.compare_digest(token, expected)
