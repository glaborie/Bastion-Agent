"""Semantic completion cache behaviour (ADR-024, IDEA-027).

The chat pipeline, DLP and egress run for real against the disposable database;
only the OmniRoute boundary is stubbed, so the model-call count in these tests is
the number of completions the cache did or did not avoid.
"""

# pylint: disable=contextmanager-generator-missing-cleanup  # astroid misreads async with

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, cast

import httpx
import pytest
import pytest_asyncio
from fakeredis import FakeAsyncRedis
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from agent.dlp.presidio import PresidioDLP, get_analyzer
from agent.dlp.vault import TokenVault
from agent.egress.sanitizer import EgressSanitizer
from agent.semantic_cache import SemanticCache
from db.models import AuditEventType, AuditLog
from db.session import get_db_session
from gateway.auth.oidc import Principal
from gateway.auth.rbac import AuthContext, get_auth_context
from gateway.main import create_app
from gateway.routers.chat import get_chat_cache, get_chat_dlp, get_chat_router, get_chat_sanitizer
from tests.conftest import requires_database
from tests.test_chat import ALICE, CONFIDENTIAL, KEY, PREFIX, PUBLIC, StubRouter

pytestmark = [pytest.mark.integration, requires_database]

GLOBEX = Principal(
    subject="globex-sub", tenant_id="globex", username="globex", roles=frozenset({"operator"})
)
QUESTION = "how do I reset my password"


@dataclass
class PairSimilarity:
    """Deterministic scores: identical text is 1.0, a configured pair is what
    the test says, everything else is 0.0."""

    pairs: dict[frozenset[str], float] = field(default_factory=dict)

    def score(self, left: str, right: str) -> float:
        if left == right:
            return 1.0
        return self.pairs.get(frozenset({left, right}), 0.0)


@dataclass
class Harness:
    client: httpx.AsyncClient
    factory: async_sessionmaker[AsyncSession]
    state: dict[str, Any]
    stub: StubRouter
    redis: FakeAsyncRedis
    cache: SemanticCache


@asynccontextmanager
async def harness(
    db_engine: AsyncEngine,
    *,
    cache_enabled: bool,
    backend: PairSimilarity | None = None,
) -> AsyncIterator[Harness]:
    redis = FakeAsyncRedis(decode_responses=True)
    vault = TokenVault(redis, key=KEY, ttl_seconds=60)
    dlp = PresidioDLP(vault, analyzer=get_analyzer())
    sanitizer = EgressSanitizer(
        vault,
        cast(Redis, redis),
        canary_prefix=PREFIX,
        canary_ttl_seconds=60,
        trip_ttl_seconds=60,
    )
    stub = StubRouter(PUBLIC, echo_last_user=True)
    cache = SemanticCache(
        cast(Redis, redis),
        backend=backend or PairSimilarity(),
        threshold=0.8,
        ttl_seconds=60,
        max_entries=10,
    )
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    app = create_app()

    async def override_db() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
            except BaseException:
                await session.rollback()
                raise
            await session.commit()

    state: dict[str, Any] = {"context": AuthContext(principal=ALICE, method="bearer")}
    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_auth_context] = lambda: state["context"]
    app.dependency_overrides[get_chat_router] = lambda: stub
    app.dependency_overrides[get_chat_dlp] = lambda: dlp
    app.dependency_overrides[get_chat_sanitizer] = lambda: sanitizer
    if cache_enabled:
        app.dependency_overrides[get_chat_cache] = lambda: cache
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=False
    ) as client:
        try:
            yield Harness(
                client=client, factory=factory, state=state, stub=stub, redis=redis, cache=cache
            )
        finally:
            await redis.aclose()


@pytest_asyncio.fixture
async def cached_api(db_engine: AsyncEngine) -> AsyncIterator[Harness]:
    async with harness(db_engine, cache_enabled=True) as pair:
        yield pair


async def ask(
    pair: Harness,
    content: str = QUESTION,
    *,
    conversation: str = "conv-cache",
    principal: Principal = ALICE,
) -> httpx.Response:
    pair.state["context"] = AuthContext(principal=principal, method="bearer")
    return await pair.client.post(
        "/v1/chat",
        json={
            "messages": [{"role": "user", "content": content}],
            "conversation_id": conversation,
        },
        headers={"X-CSRF-Token": "csrf-token"},
    )


async def response_rows(pair: Harness, conversation: str) -> list[AuditLog]:
    async with pair.factory() as session:
        return list(
            (
                await session.execute(
                    select(AuditLog)
                    .where(
                        AuditLog.session_id == conversation,
                        AuditLog.event_type.in_(
                            (
                                AuditEventType.DLP_REDACTION,
                                AuditEventType.EGRESS_FILTERED,
                                AuditEventType.RESPONSE_SENT,
                            )
                        ),
                    )
                    .order_by(AuditLog.id)
                )
            ).scalars()
        )


async def test_two_identical_turns_are_one_model_call(cached_api: Harness) -> None:
    pair = cached_api

    first = await ask(pair)
    second = await ask(pair)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert pair.stub.complete_calls == 1
    assert second.json()["message"]["content"] == first.json()["message"]["content"]
    assert second.json()["model"] == "semantic-cache"

    # The hit is still a full turn on the ledger: DLP and egress ran.
    rows = await response_rows(pair, "conv-cache")
    assert [row.event_type for row in rows] == [
        AuditEventType.DLP_REDACTION,
        AuditEventType.EGRESS_FILTERED,
        AuditEventType.RESPONSE_SENT,
        AuditEventType.DLP_REDACTION,
        AuditEventType.EGRESS_FILTERED,
        AuditEventType.RESPONSE_SENT,
    ]
    answers = [row for row in rows if row.event_type is AuditEventType.RESPONSE_SENT]
    assert [row.metadata_json["cache_hit"] for row in answers] == [False, True]


async def test_a_paraphrase_above_the_threshold_hits_and_a_near_miss_does_not(
    db_engine: AsyncEngine,
) -> None:
    backend = PairSimilarity(pairs={frozenset({QUESTION, "how can i reset my password"}): 0.95})
    async with harness(db_engine, cache_enabled=True, backend=backend) as pair:
        assert (await ask(pair)).status_code == 200
        paraphrase = await ask(pair, "how can i reset my password")
        assert paraphrase.status_code == 200
        assert pair.stub.complete_calls == 1
        assert paraphrase.json()["message"]["content"] == QUESTION

        near_miss = await ask(pair, "how do i delete my account")
        assert near_miss.status_code == 200
        assert pair.stub.complete_calls == 2
        assert near_miss.json()["message"]["content"] == "how do i delete my account"


async def test_the_scope_never_crosses_tenant_alias_or_label(cached_api: Harness) -> None:
    pair = cached_api

    # Identical prompt text, public route: stored under acme/cloud-primary/PUBLIC.
    assert (await ask(pair)).status_code == 200
    assert pair.stub.complete_calls == 1

    # Same text, same tenant, but a confidential classification pins local-llama.
    pair.stub.classification = CONFIDENTIAL
    assert (await ask(pair, conversation="conv-label")).status_code == 200
    assert pair.stub.complete_calls == 2, "a local answer must never read the cloud entry"

    # Same text, same route, different tenant.
    pair.stub.classification = PUBLIC
    assert (await ask(pair, conversation="conv-tenant", principal=GLOBEX)).status_code == 200
    assert pair.stub.complete_calls == 3, "a tenant must never read another tenant's entry"


async def test_a_marker_turn_is_never_served_from_another_session(cached_api: Harness) -> None:
    pair = cached_api
    pii = "my email is alice@example.com and it does not work"

    first = await ask(pair, pii, conversation="conv-a")
    second = await ask(pair, pii, conversation="conv-b")

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert "alice@example.com" in first.json()["message"]["content"]
    assert "{{ENTITY:" not in first.json()["message"]["content"]
    # A marker minted in conv-a must not be replayed into conv-b: it is a miss.
    assert pair.stub.complete_calls == 2
    assert "{{ENTITY:" not in second.json()["message"]["content"]


async def test_the_cache_is_off_by_default(db_engine: AsyncEngine) -> None:
    async with harness(db_engine, cache_enabled=False) as pair:
        assert (await ask(pair)).status_code == 200
        assert (await ask(pair)).status_code == 200
        assert pair.stub.complete_calls == 2

        answers = [
            row
            for row in await response_rows(pair, "conv-cache")
            if row.event_type is AuditEventType.RESPONSE_SENT
        ]
        assert all(row.metadata_json["cache_hit"] is False for row in answers)


async def test_a_marker_bearing_entry_is_never_stored_or_served() -> None:
    redis = FakeAsyncRedis(decode_responses=True)
    cache = SemanticCache(
        cast(Redis, redis),
        backend=PairSimilarity(),
        threshold=0.5,
        ttl_seconds=60,
        max_entries=5,
    )
    scope = {"tenant_id": "acme", "alias": "cloud-primary", "label": "PUBLIC"}

    await cache.store(**scope, prompt=QUESTION, answer="mail {{ENTITY:EMAIL_ADDRESS_1}}")
    assert await cache.lookup(**scope, prompt=QUESTION) is None

    # A planted entry stands in for a corrupted or older record: the read
    # refuses it too, so a replay can never deliver an unresolved token.
    await redis.set(
        "semantic_cache:v1:acme:cloud-primary:PUBLIC",
        json.dumps({"entries": [{"prompt": QUESTION, "answer": "{{ENTITY:PERSON_1}}"}]}),
    )
    assert await cache.lookup(**scope, prompt=QUESTION) is None
    await redis.aclose()
