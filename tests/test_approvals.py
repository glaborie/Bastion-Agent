"""Four-eyes approval model and HMAC ticket tests (HANDOVER_SPEC §3.2)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import (
    ApprovalStatus,
    PendingApproval,
    fingerprint_request,
    hash_approval_token,
    sign_approval_token,
    utcnow,
    verify_approval_token,
)
from tests.conftest import requires_database

SECRET = "unit-test-approval-hmac-secret"
ARGUMENTS: dict[str, Any] = {"path": "/srv/reports/q3.csv", "content": "revenue"}


def build_ticket(
    *,
    issued_at: datetime | None = None,
    ttl_seconds: int = 900,
    ticket_id: uuid.UUID | None = None,
    initiator_id: str = "alice",
    tenant_id: str = "acme",
    tool_name: str = "execute_file_write",
    arguments: dict[str, Any] | None = None,
) -> tuple[PendingApproval, str]:
    """Construct an unsaved ticket plus the plaintext token handed to the caller."""
    issued = issued_at or utcnow()
    expires_at = PendingApproval.expiry_for(issued, ttl_seconds)
    identifier = ticket_id or uuid.uuid4()
    tool_arguments = ARGUMENTS if arguments is None else arguments
    fingerprint = fingerprint_request(tool_name, tool_arguments)
    token = sign_approval_token(
        ticket_id=identifier,
        request_fingerprint=fingerprint,
        expires_at=expires_at,
        secret=SECRET,
    )
    ticket = PendingApproval(
        ticket_id=identifier,
        session_id="sess-four-eyes",
        tenant_id=tenant_id,
        initiator_id=initiator_id,
        tool_name=tool_name,
        tool_arguments=tool_arguments,
        required_role="operator",
        request_fingerprint=fingerprint,
        approval_token_hash=hash_approval_token(token),
        token_expires_at=expires_at,
        created_at=issued,
    )
    return ticket, token


# ---------------------------------------------------------------------------
# Token primitives
# ---------------------------------------------------------------------------


def test_approval_token_roundtrip() -> None:
    ticket, token = build_ticket()
    assert verify_approval_token(
        token=token,
        ticket_id=ticket.ticket_id,
        request_fingerprint=ticket.request_fingerprint,
        expires_at=ticket.token_expires_at,
        secret=SECRET,
    )


def test_approval_token_is_bound_to_the_exact_request() -> None:
    ticket, token = build_ticket()
    other_fingerprint = fingerprint_request(
        "execute_file_write", {"path": "/etc/shadow", "content": "exfiltrate"}
    )
    assert not verify_approval_token(
        token=token,
        ticket_id=ticket.ticket_id,
        request_fingerprint=other_fingerprint,
        expires_at=ticket.token_expires_at,
        secret=SECRET,
    )


def test_approval_token_is_bound_to_ticket_and_expiry() -> None:
    ticket, token = build_ticket()
    assert not verify_approval_token(
        token=token,
        ticket_id=uuid.uuid4(),
        request_fingerprint=ticket.request_fingerprint,
        expires_at=ticket.token_expires_at,
        secret=SECRET,
    )
    assert not verify_approval_token(
        token=token,
        ticket_id=ticket.ticket_id,
        request_fingerprint=ticket.request_fingerprint,
        expires_at=ticket.token_expires_at + timedelta(seconds=60),
        secret=SECRET,
    )


def test_tampered_token_is_rejected() -> None:
    ticket, token = build_ticket()
    tampered = token[:-4] + ("aaaa" if not token.endswith("aaaa") else "bbbb")
    assert not verify_approval_token(
        token=tampered,
        ticket_id=ticket.ticket_id,
        request_fingerprint=ticket.request_fingerprint,
        expires_at=ticket.token_expires_at,
        secret=SECRET,
    )


def test_fingerprint_tracks_every_argument() -> None:
    assert fingerprint_request("t", {"a": 1}) == fingerprint_request("t", {"a": 1})
    assert fingerprint_request("t", {"a": 1}) != fingerprint_request("t", {"a": 2})
    assert fingerprint_request("t", {"a": 1}) != fingerprint_request("u", {"a": 1})
    assert len(fingerprint_request("t", {"a": 1})) == 64


def test_non_positive_ttl_is_rejected() -> None:
    with pytest.raises(ValueError, match="TTL"):
        PendingApproval.expiry_for(utcnow(), 0)


# ---------------------------------------------------------------------------
# Application-level four-eyes semantics
# ---------------------------------------------------------------------------


def test_initiator_cannot_decide_their_own_ticket() -> None:
    ticket, _token = build_ticket()
    assert ticket.is_decidable is True
    assert ticket.can_be_decided_by("bob") is True
    assert ticket.can_be_decided_by("alice") is False


def test_expired_ticket_is_not_decidable() -> None:
    expired, _token = build_ticket(issued_at=utcnow() - timedelta(hours=1))
    assert expired.is_expired is True
    assert expired.is_decidable is False
    assert expired.can_be_decided_by("bob") is False


# ---------------------------------------------------------------------------
# Database enforcement (defence in depth)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@requires_database
async def test_database_rejects_self_approval(session: AsyncSession) -> None:
    ticket, _token = build_ticket()
    session.add(ticket)
    await session.flush()

    ticket.status = ApprovalStatus.APPROVED
    ticket.approver_id = ticket.initiator_id  # the four-eyes violation
    ticket.decided_at = utcnow()

    with pytest.raises(IntegrityError, match=r"four_eyes_separation|ck_pending_approvals"):
        await session.flush()
    await session.rollback()


@pytest.mark.integration
@requires_database
async def test_database_accepts_a_secondary_approver(session: AsyncSession) -> None:
    ticket, _token = build_ticket()
    ticket_id = ticket.ticket_id
    session.add(ticket)
    await session.flush()

    ticket.status = ApprovalStatus.APPROVED
    ticket.approver_id = "bob"
    ticket.decided_at = utcnow()
    await session.flush()

    session.expire_all()
    reloaded = await session.get(PendingApproval, ticket_id)
    assert reloaded is not None
    assert reloaded.status == ApprovalStatus.APPROVED
    assert reloaded.approver_id == "bob"
    assert reloaded.can_be_decided_by("carol") is False


@pytest.mark.integration
@requires_database
async def test_database_rejects_approval_without_decision_metadata(
    session: AsyncSession,
) -> None:
    ticket, _token = build_ticket()
    session.add(ticket)
    await session.flush()

    ticket.status = ApprovalStatus.APPROVED  # no approver_id, no decided_at
    with pytest.raises(IntegrityError, match=r"terminal_decision_recorded|ck_pending_approvals"):
        await session.flush()
    await session.rollback()


@pytest.mark.integration
@requires_database
async def test_utc_timestamps_survive_the_round_trip(session: AsyncSession) -> None:
    issued = datetime(2026, 11, 9, 12, 0, 0, 123456, tzinfo=UTC)
    ticket, _token = build_ticket(issued_at=issued)
    ticket_id = ticket.ticket_id
    session.add(ticket)
    await session.flush()
    session.expire_all()

    reloaded = await session.get(PendingApproval, ticket_id)
    assert reloaded is not None
    assert reloaded.token_expires_at == issued + timedelta(seconds=900)
