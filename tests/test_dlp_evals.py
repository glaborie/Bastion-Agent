"""Golden DLP gate (ADR-006): deterministic, zero-tolerance redaction recall.

The metric is a real DeepEval ``BaseMetric`` but scores exact entity-type
coverage rather than an LLM judgement, so the gate is reproducible offline and
never inspects a raw matched value. Routing labels are gated separately in
``test_classifier_evals.py``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Final, cast

import pytest
import pytest_asyncio
from deepeval.metrics import BaseMetric
from deepeval.test_case import LLMTestCase
from fakeredis import FakeAsyncRedis

from agent.dlp.presidio import PresidioDLP, RedactionResult, get_analyzer
from agent.dlp.vault import TokenVault
from tests.goldens import Golden, load_goldens

KEY: Final[bytes] = b"g" * 32
GOLDENS = load_goldens()
REDACTION_CASES = [golden for golden in GOLDENS if golden.expected_redactions]
CLEAN_CASES = [
    golden
    for golden in GOLDENS
    if golden.category in {"public", "borderline"} and not golden.expected_redactions
]


class DLPRedactionMetric(BaseMetric):
    """Score 1.0 only when every expected entity type was detected."""

    def __init__(self, expected_entities: Sequence[str], threshold: float = 1.0) -> None:
        self.expected_entities = frozenset(expected_entities)
        self.threshold = threshold
        self.async_mode = False
        self.include_reason = True
        self.score: float | None = None
        self.success = False
        self.reason = ""

    def measure(self, test_case: LLMTestCase, *args: object, **kwargs: object) -> float:
        result = cast(RedactionResult, args[0])
        detected = set(result.entity_types)
        missing = self.expected_entities - detected
        self.score = 1.0 if not missing else 0.0
        self.reason = "" if not missing else "missing entities: " + ", ".join(sorted(missing))
        self.success = self.score >= self.threshold
        return self.score

    async def a_measure(self, test_case: LLMTestCase, *args: object, **kwargs: object) -> float:
        return self.measure(test_case, *args, **kwargs)

    def is_successful(self) -> bool:
        return self.success

    @property
    def __name__(self) -> str:
        return "DLP Redaction"


@pytest_asyncio.fixture
async def dlp() -> AsyncIterator[PresidioDLP]:
    redis = FakeAsyncRedis(decode_responses=True)
    vault = TokenVault(redis, key=KEY, ttl_seconds=60)
    try:
        yield PresidioDLP(vault, analyzer=get_analyzer())
    finally:
        await redis.aclose()


def test_corpus_covers_every_identifier_family() -> None:
    families = {entity for golden in REDACTION_CASES for entity in golden.expected_redactions}
    assert {"EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "CREDIT_CARD", "API_KEY"} <= families


@pytest.mark.parametrize("golden", REDACTION_CASES, ids=lambda item: item.ident)
async def test_golden_redaction_is_zero_tolerance(dlp: PresidioDLP, golden: Golden) -> None:
    result = await dlp.redact(golden.prompt, f"golden-{golden.ident}")
    metric = DLPRedactionMetric(golden.expected_redactions)
    case = LLMTestCase(input=golden.prompt, actual_output=result.text)
    score = metric.measure(case, result)
    assert score == golden.expected_score, f"{golden.ident}: {metric.reason or 'failed'}"
    for entity in result.entities:
        assert entity.token in result.text


@pytest.mark.parametrize("golden", CLEAN_CASES, ids=lambda item: item.ident)
async def test_benign_prompts_are_not_over_redacted(dlp: PresidioDLP, golden: Golden) -> None:
    result = await dlp.redact(golden.prompt, f"clean-{golden.ident}")
    assert not result.redacted, f"{golden.ident}: unexpected {result.entity_types}"
