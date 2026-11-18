"""The handoff transcript reads the whole conversation, not one turn (IDEA-074).

The shared dashboard app fixture and identities live in ``tests/test_dashboard.py``;
this module keeps the multi-turn transcript cases together, and needs the same
disposable PostgreSQL instance.
"""

# pylint: disable=redefined-outer-name  # pytest fixtures

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from db.audit import append_audit_event
from db.escrow import record_payload_escrow
from db.models import AuditEventType, AuditLog, EscrowKind, PayloadEscrow, utcnow
from gateway.auth.rbac import AuthContext
from tests.conftest import requires_database
from tests.test_dashboard import ADMIN, dashboard_app, session_context

pytestmark = [pytest.mark.integration, requires_database]


@pytest_asyncio.fixture
async def api(
    db_engine: AsyncEngine,
) -> AsyncIterator[tuple[httpx.AsyncClient, dict[str, AuthContext]]]:
    # pylint: disable=contextmanager-generator-missing-cleanup  # astroid misreads async with
    async with dashboard_app(db_engine) as pair:
        yield pair


async def seed_transcript_turn(
    factory: async_sessionmaker[AsyncSession],
    *,
    conversation_id: str,
    history: list[dict[str, str]],
    answer: str,
) -> tuple[int, int]:
    """One escrowed request/answer pair, written the way ``/v1/chat`` writes it."""
    async with factory() as session:
        request_row = await append_audit_event(
            session,
            actor_id="alice-sub",
            tenant_id="acme",
            event_type=AuditEventType.INPUT_RECEIVED,
            session_id=conversation_id,
            payload=history,
        )
        await record_payload_escrow(session, request_row, history)
        answer_row = await append_audit_event(
            session,
            actor_id="alice-sub",
            tenant_id="acme",
            event_type=AuditEventType.RESPONSE_SENT,
            session_id=conversation_id,
            payload=answer,
        )
        await record_payload_escrow(session, answer_row, answer, kind=EscrowKind.EGRESS_DELIVERED)
        await session.commit()
        return int(request_row.id), int(answer_row.id)


def transcript_lines(html: str) -> list[str]:
    """The rendered ``<pre>`` as one line per turn, in page order."""
    block = re.search(r"<pre>(.*?)</pre>", html, re.DOTALL)
    assert block is not None
    return [line.strip() for line in block.group(1).splitlines() if line.strip()]


async def transcript_accessed_count(factory: async_sessionmaker[AsyncSession]) -> int:
    async with factory() as session:
        rows = list(
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.event_type == AuditEventType.ESCROW_ACCESSED)
                )
            ).scalars()
        )
    return len(rows)


async def test_the_transcript_shows_every_turn_in_order(
    api: tuple[httpx.AsyncClient, Any],
    db_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from settings import reset_settings_cache

    monkeypatch.setenv("PAYLOAD_ESCROW_ENABLED", "true")
    reset_settings_cache()
    client, state = api
    state["context"] = session_context(ADMIN)
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    turns = [
        ("the button is not working", "Sorry about that. Which button?"),
        ("seriously, the button is not working again", "Let me look again."),
        ("it still fails", "Could you share the error text?"),
    ]
    history: list[dict[str, str]] = []
    for question, answer in turns:
        history = [*history, {"role": "user", "content": question}]
        await seed_transcript_turn(
            factory, conversation_id="conv-turns", history=history, answer=answer
        )

    response = await client.post(
        "/api/handoffs/conv-turns/transcript", headers={"X-CSRF-Token": "csrf-token"}
    )

    assert response.status_code == 200, response.text
    # Each request resends the conversation so far; the panel must not replay it.
    assert transcript_lines(response.text) == [
        f"user: {turns[0][0]}",
        f"assistant: {turns[0][1]}",
        f"user: {turns[1][0]}",
        f"assistant: {turns[1][1]}",
        f"user: {turns[2][0]}",
        f"assistant: {turns[2][1]}",
    ]
    assert await transcript_accessed_count(factory) == 6  # one per decrypted record


async def test_the_transcript_is_capped_and_keeps_the_newest_rows(
    api: tuple[httpx.AsyncClient, Any],
    db_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from settings import reset_settings_cache

    monkeypatch.setenv("PAYLOAD_ESCROW_ENABLED", "true")
    monkeypatch.setenv("HANDOFF_TRANSCRIPT_MAX_RECORDS", "3")
    reset_settings_cache()
    client, state = api
    state["context"] = session_context(ADMIN)
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    turns = [(f"question {index}", f"answer {index}") for index in (1, 2, 3)]
    history: list[dict[str, str]] = []
    for question, answer in turns:
        history = [*history, {"role": "user", "content": question}]
        await seed_transcript_turn(
            factory, conversation_id="conv-capped", history=history, answer=answer
        )

    response = await client.post(
        "/api/handoffs/conv-capped/transcript", headers={"X-CSRF-Token": "csrf-token"}
    )

    assert response.status_code == 200, response.text
    # The window starts on a request, so the third request replays the history it
    # carries; answers 1 and 2 fall outside the cap.
    assert transcript_lines(response.text) == [
        "user: question 1",
        "user: question 2",
        "user: question 3",
        "assistant: answer 3",
    ]
    # Three rows read, one dropped as an orphan answer: two decrypts.
    assert await transcript_accessed_count(factory) == 2


async def test_an_expired_entry_renders_as_a_gap(
    api: tuple[httpx.AsyncClient, Any],
    db_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from settings import reset_settings_cache

    monkeypatch.setenv("PAYLOAD_ESCROW_ENABLED", "true")
    reset_settings_cache()
    client, state = api
    state["context"] = session_context(ADMIN)
    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    questions = [f"question {index}" for index in (1, 2, 3)]
    answers = [f"answer {index}" for index in (1, 2, 3)]
    history = [{"role": "user", "content": questions[0]}]
    _, first_answer_id = await seed_transcript_turn(
        factory, conversation_id="conv-gap", history=history, answer=answers[0]
    )
    for index in (1, 2):
        history = [*history, {"role": "user", "content": questions[index]}]
        await seed_transcript_turn(
            factory, conversation_id="conv-gap", history=history, answer=answers[index]
        )
    async with factory() as session:
        await session.execute(
            update(PayloadEscrow)
            .where(PayloadEscrow.audit_log_id == first_answer_id)
            .values(
                created_at=utcnow() - timedelta(hours=25),
                expires_at=utcnow() - timedelta(hours=1),
            )
        )
        await session.commit()

    response = await client.post(
        "/api/handoffs/conv-gap/transcript", headers={"X-CSRF-Token": "csrf-token"}
    )

    assert response.status_code == 200, response.text
    assert transcript_lines(response.text) == [
        f"user: {questions[0]}",
        f"unavailable: audit row {first_answer_id}: escrow expired or missing",
        f"user: {questions[1]}",
        f"assistant: {answers[1]}",
        f"user: {questions[2]}",
        f"assistant: {answers[2]}",
    ]
    assert await transcript_accessed_count(factory) == 5
