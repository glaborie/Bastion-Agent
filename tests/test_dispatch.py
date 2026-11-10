"""Host-dispatch verdict tests (ADR-011).

Only the systemic AVX2-only signature — every benign sentinel blocked while the
injection sentinel is still detected — may exempt the golden gate. Every partial
mismatch must fall through so the gate reports it.
"""

from __future__ import annotations

import pytest

from agent.routing.classifier import Classification, Sensitivity
from agent.routing.dispatch import SENTINELS, DispatchVerdict, Sentinel, evaluate

BENIGN = [sentinel for sentinel in SENTINELS if sentinel.expected_label == "PUBLIC"]


class StubClassifier:
    """Returns one canned decision per sentinel prompt."""

    def __init__(self, decisions: dict[str, Classification]) -> None:
        self._by_prompt = decisions

    def classify(self, text: str) -> Classification:
        return self._by_prompt[text]


def _decision(label: str, reason: str, confidence: float = 0.92) -> Classification:
    return Classification(Sensitivity(label), confidence, "stub", reason=reason)


def _host(*, benign_blocked: int = 0, injection_public: bool = False) -> StubClassifier:
    """A host that blocks the first ``benign_blocked`` benign sentinels."""
    decisions: dict[str, Classification] = {}
    blocked = 0
    for sentinel in SENTINELS:
        if sentinel.expected_label == "PUBLIC":
            if blocked < benign_blocked:
                decisions[sentinel.prompt] = _decision("CONFIDENTIAL", "unsafe_content")
                blocked += 1
            else:
                decisions[sentinel.prompt] = _decision("PUBLIC", "public_content", 0.99)
        elif injection_public:
            decisions[sentinel.prompt] = _decision("PUBLIC", "public_content", 0.99)
        else:
            decisions[sentinel.prompt] = _decision("CONFIDENTIAL", sentinel.expected_reason)
    return StubClassifier(decisions)


def _verdict(classifier: StubClassifier) -> DispatchVerdict:
    return evaluate(classifier)  # type: ignore[arg-type]


def test_a_reference_host_is_not_exempted() -> None:
    verdict = _verdict(_host())
    assert verdict.name == "reference"
    assert verdict.benign_blocked == 0
    assert verdict.positives_detected == 1


def test_every_benign_row_blocked_is_the_dispatch_anomaly() -> None:
    verdict = _verdict(_host(benign_blocked=len(BENIGN)))
    assert verdict.name == "dispatch_anomaly"
    assert verdict.benign_blocked == len(BENIGN)
    assert verdict.positives_detected == 1


def test_a_single_flipped_benign_row_is_not_exempted() -> None:
    verdict = _verdict(_host(benign_blocked=1))
    assert verdict.name == "reference"
    assert verdict.benign_blocked == 1


def test_a_lost_positive_is_not_exempted() -> None:
    """Every benign row blocked *and* the injection row lost is not the signature."""
    verdict = _verdict(_host(benign_blocked=len(BENIGN), injection_public=True))
    assert verdict.name == "reference"
    assert verdict.positives_detected == 0


def test_the_verdict_follows_the_decision_table_not_the_raw_scores() -> None:
    verdict = _verdict(_host(benign_blocked=len(BENIGN)))
    reasons = {item.sentinel.ident: item.reason for item in verdict.results}
    assert reasons["public-haiku-048"] == "unsafe_content"
    assert reasons["injection-direct-038"] == "prompt_injection_detected"


@pytest.mark.parametrize("sentinel", SENTINELS, ids=lambda item: item.ident)
def test_every_sentinel_has_a_baseline_score_and_expectation(sentinel: Sentinel) -> None:
    assert sentinel.expected_label in {"PUBLIC", "CONFIDENTIAL"}
    assert 0.0 <= sentinel.injection <= 1.0
    assert 0.0 <= sentinel.unsafe <= 1.0
