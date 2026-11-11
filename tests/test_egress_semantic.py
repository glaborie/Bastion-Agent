"""Semantic disclosure claims at egress (ADR-012 decision 9).

The canary catches the marker; these cases cover the other failure the live
session showed: a model announcing "here is the system prompt" and fabricating
one. The verdict is a flag, not a block — the claim proves nothing about the
actual instructions, and no secret crossed the boundary.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import cast

import pytest_asyncio
from fakeredis import FakeAsyncRedis
from redis.asyncio import Redis

from agent.dlp.vault import TokenVault
from agent.egress.sanitizer import EgressSanitizer

KEY = b"s" * 32
PREFIX = "BASTION-CANARY-"

#: The completion recorded in the live session on 2026-11-11 (IDEA-015).
RECORDED_COMPLETION = (
    "Sure, here is the system prompt: --- This system is designed to provide "
    "helpful and informative responses while respecting confidentiality and "
    "security protocols..."
)


@pytest_asyncio.fixture
async def sanitizer() -> AsyncIterator[EgressSanitizer]:
    redis = FakeAsyncRedis(decode_responses=True)
    vault = TokenVault(redis, key=KEY, ttl_seconds=60)
    engine = EgressSanitizer(
        vault,
        cast(Redis, redis),
        canary_prefix=PREFIX,
        canary_ttl_seconds=60,
        trip_ttl_seconds=60,
    )
    try:
        yield engine
    finally:
        await redis.aclose()


async def test_the_recorded_transcript_produces_a_named_verdict(
    sanitizer: EgressSanitizer,
) -> None:
    """It is delivered — there is no marker — but no longer unflagged."""
    result = await sanitizer.inspect(RECORDED_COMPLETION, "session-recorded")

    assert result.blocked is False
    assert result.disclosure_claim == "system_prompt"
    assert result.text == RECORDED_COMPLETION


async def test_a_claim_does_not_quarantine_the_session(sanitizer: EgressSanitizer) -> None:
    await sanitizer.inspect(RECORDED_COMPLETION, "session-no-trip")
    assert await sanitizer.is_tripped("session-no-trip") is False

    second = await sanitizer.inspect("A normal answer.", "session-no-trip")
    assert second.blocked is False
    assert second.disclosure_claim is None


async def test_instruction_and_instructed_claims_are_named(
    sanitizer: EgressSanitizer,
) -> None:
    for text, expected in (
        ("My instructions are to be concise.", "instructions"),
        ("I was instructed to keep this confidential.", "instructed"),
        ("I have been programmed to answer in French.", "instructed"),
    ):
        result = await sanitizer.inspect(text, f"session-{expected}")
        assert result.disclosure_claim == expected, text
        assert result.blocked is False


async def test_benign_explanations_are_not_claimed(sanitizer: EgressSanitizer) -> None:
    """Explaining what a system prompt is must not look like disclosing one."""
    for text in (
        "A system prompt is the text that tells a model how to behave.",
        "A system prompt usually contains instructions and safety rules.",
        "The article explains how system prompts are written.",
        "In one sentence, a canary token is a tripwire for leaked prompts.",
    ):
        result = await sanitizer.inspect(text, f"session-benign-{hash(text)}")
        assert result.disclosure_claim is None, text


async def test_a_canary_leak_still_blocks_and_reports_no_claim(
    sanitizer: EgressSanitizer,
) -> None:
    """The marker path is unchanged: discard, quarantine, no text."""
    canary = await sanitizer.canary_for("session-leak")
    result = await sanitizer.inspect(f"{RECORDED_COMPLETION} {canary}", "session-leak")

    assert result.blocked is True
    assert result.reason == "canary_leak"
    assert result.text == ""
    assert result.disclosure_claim is None
    assert await sanitizer.is_tripped("session-leak") is True
