"""Signed envelopes for identity-bearing worker jobs (ADR-018).

The ARQ queue is a Redis list. Anyone who can write to it can enqueue any job
name with any keyword arguments, so a job that carries an identity is only as
trustworthy as the party that wrote it. Before this module the worker rebuilt
:class:`~agent.tools.decorator.AgentContext` straight from the payload: a forged
``actor_id`` produced tickets the real operator would approve, and a forged
``tenant_id`` crossed the tenant boundary the rest of the stack enforces.

Every identity-bearing job therefore travels inside an envelope minted by the
enqueuer and verified by the worker with a key the worker never leaks:

``v1|<job kind>|<sha256 of the canonical fields>|<nonce>|<expires_at>``

signed with HMAC-SHA256. The worker checks the signature in constant time, then
consumes the nonce once so a captured payload cannot be replayed. The envelope
proves *who minted the job*, not *what the queue contains*: an attacker holding
``JOB_SIGNING_SECRET`` is equivalent to an administrator, which is why the
secret is separate from ``APPROVAL_HMAC_SECRET`` (a leaked job key must not mint
approval capability tokens) and refused at startup outside local development.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from redis.asyncio import Redis

from db.models import canonical_timestamp, hash_payload, utcnow

#: Envelope format tag; bump only with a migration for queued jobs.
JOB_SIGNATURE_VERSION: Final[str] = "v1"

#: Job names whose payload asserts a principal. ``resume_tool_job`` is included
#: even though it carries no roles: its ticket id is the only input, and signing
#: it keeps one mint/verify path for every enqueue site.
TOOL_JOB: Final[str] = "execute_tool_job"
RESUME_JOB: Final[str] = "resume_tool_job"
DEMO_JOB: Final[str] = "run_demo_scenario_job"

#: Redis prefix for consumed nonces; the TTL is the signature TTL.
_NONCE_KEY_PREFIX: Final[str] = "job:nonce:"


class JobSignatureError(Exception):
    """The job payload was not minted by a trusted enqueuer."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def tool_job_fields(
    *,
    tool_name: str,
    actor_id: str,
    tenant_id: str,
    session_id: str,
    roles: list[str] | None,
    arguments: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """The exact field set a tool job signs.

    Roles are sorted and arguments are taken as-is: the worker must rebuild this
    dict from the payload it received, so every value has to round-trip through
    ARQ's JSON encoding unchanged.
    """
    return {
        "tool_name": tool_name,
        "actor_id": actor_id,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "roles": sorted(roles or ()),
        "arguments": dict(arguments or {}),
    }


def demo_job_fields(
    *,
    run_id: str,
    scenario_id: str,
    actor_id: str,
    tenant_id: str,
    roles: list[str] | None,
    session_id: str,
) -> dict[str, Any]:
    """The exact field set a demo-run job signs."""
    return {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "actor_id": actor_id,
        "tenant_id": tenant_id,
        "roles": sorted(roles or ()),
        "session_id": session_id,
    }


def resume_job_fields(*, ticket_id: str, tenant_id: str) -> dict[str, Any]:
    """The exact field set a resume job signs."""
    return {"ticket_id": ticket_id, "tenant_id": tenant_id}


def _message(kind: str, fields: Mapping[str, Any], nonce: str, expires_at: datetime) -> bytes:
    return "|".join(
        (
            JOB_SIGNATURE_VERSION,
            kind,
            hash_payload(dict(fields)),
            nonce,
            canonical_timestamp(expires_at),
        )
    ).encode("utf-8")


def sign_job(
    kind: str,
    fields: Mapping[str, Any],
    *,
    secret: str,
    ttl_seconds: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Mint the envelope kwargs for one job payload.

    Returns the three keys the worker expects appended to the enqueue call, so a
    caller cannot sign one payload and send another.
    """
    if not secret:
        raise ValueError("job signing secret must not be empty")
    if ttl_seconds <= 0:
        raise ValueError("job signature TTL must be positive")
    issued = now or utcnow()
    expires_at = issued + timedelta(seconds=ttl_seconds)
    nonce = uuid.uuid4().hex
    digest = hmac.new(
        secret.encode("utf-8"),
        _message(kind, fields, nonce, expires_at),
        hashlib.sha256,
    ).digest()
    return {
        "job_nonce": nonce,
        "job_expires_at": canonical_timestamp(expires_at),
        "job_signature": digest.hex(),
    }


def verify_job(
    kind: str,
    fields: Mapping[str, Any],
    *,
    nonce: str,
    expires_at: str,
    signature: str,
    secret: str,
    now: datetime | None = None,
) -> None:
    """Raise :class:`JobSignatureError` unless the envelope proves this payload.

    Verification is constant-time over the signature and rejects an envelope
    whose expiry has passed, so a captured payload has a bounded life even before
    the nonce is consulted.
    """
    if not (nonce and expires_at and signature):
        raise JobSignatureError("unsigned_job")
    if not secret:
        raise JobSignatureError("no_signing_key")
    try:
        deadline = datetime.fromisoformat(expires_at)
    except ValueError as exc:
        raise JobSignatureError("malformed_envelope") from exc
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    moment = now or utcnow()
    if deadline <= moment:
        raise JobSignatureError("expired_job")

    expected = hmac.new(
        secret.encode("utf-8"),
        _message(kind, fields, nonce, deadline),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise JobSignatureError("bad_signature")


async def consume_nonce(
    redis: Redis,
    nonce: str,
    *,
    ttl_seconds: int,
) -> bool:
    """Claim a job nonce exactly once; ``False`` means it was already used.

    The nonce outlives the signature it belongs to, so a replay cannot wait for
    the key to lapse and try again. A Redis failure propagates: a worker that
    cannot prove single use must not execute the job.
    """
    if ttl_seconds <= 0:
        raise ValueError("nonce TTL must be positive")
    claimed = await redis.set(f"{_NONCE_KEY_PREFIX}{nonce}", "1", nx=True, ex=ttl_seconds)
    return bool(claimed)


async def verify_and_consume(
    redis: Redis,
    kind: str,
    fields: Mapping[str, Any],
    *,
    nonce: str,
    expires_at: str,
    signature: str,
    secret: str,
    ttl_seconds: int,
    now: datetime | None = None,
) -> None:
    """Verify the envelope, then burn the nonce.

    Verification runs first so an unsigned payload cannot exhaust the nonce
    namespace, and the nonce TTL is measured from the signature deadline rather
    than from arrival: a job that sat in the queue for most of its window still
    cannot be replayed after it lapses.
    """
    verify_job(
        kind,
        fields,
        nonce=nonce,
        expires_at=expires_at,
        signature=signature,
        secret=secret,
        now=now,
    )
    deadline = datetime.fromisoformat(expires_at)
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    moment = now or utcnow()
    remaining = max(int((deadline - moment).total_seconds()), 1)
    if not await consume_nonce(redis, nonce, ttl_seconds=max(remaining, ttl_seconds)):
        raise JobSignatureError("replayed_job")
