"""Zero-tolerance classifier gate over the ADR-006 golden corpus.

The corpus mixes two layers: Presidio owns identifier redaction (tested in
``test_dlp_evals.py``) and the sensitivity classifier owns the routing verdict.
This module gates the verdict: every row with an ``expected_label`` must match,
and every row documents why it exists.

The real-model test is skipped when the ADR-011 graphs are not downloaded under
``models/``. Thresholds come from :class:`Settings` with ``_env_file=None`` so
the gate checks the coded defaults, not a developer's local ``.env``.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Protocol

import pytest

from agent.routing.classifier import (
    CATEGORY_REASONS,
    Classification,
    Sensitivity,
    SensitivityClassifier,
)
from agent.routing.dispatch import SENTINELS
from settings import Settings
from tests.goldens import Golden, load_goldens

MODELS = Path("models")
INJECTION_GRAPH = MODELS / "prompt-injection-guard-small/onnx/model_quantized.onnx"
SAFETY_GRAPH = MODELS / "content-safety-guard-small/onnx/model_quantized.onnx"
GOLDENS = load_goldens()

MUST_BLOCK = frozenset({"pii", "corporate", "injection", "privacy", *CATEGORY_REASONS})
REQUIRED_CATEGORIES = frozenset(
    {
        "pii",
        "corporate",
        "injection",
        "privacy",
        "fraud_manipulation",
        "criminal_planning",
        "unauthorized_advice",
        "public",
        "borderline",
    }
)


# -- corpus integrity ------------------------------------------------------
def test_corpus_is_large_enough_and_covers_every_category() -> None:
    assert len(GOLDENS) >= 25, "ADR-006 requires at least 25 golden cases"
    present = {golden.category for golden in GOLDENS}
    assert present >= REQUIRED_CATEGORIES, f"missing categories: {REQUIRED_CATEGORIES - present}"


def test_corpus_ids_are_unique() -> None:
    identifiers = [golden.ident for golden in GOLDENS]
    assert len(identifiers) == len(set(identifiers))


def test_every_must_block_row_asserts_a_label_or_documents_a_gap() -> None:
    for golden in GOLDENS:
        if golden.category in MUST_BLOCK:
            assert (
                golden.expected_label == "CONFIDENTIAL"
                or golden.known_gap
                or golden.expected_redactions
            ), golden.ident
        if golden.known_gap:
            assert golden.expected_label is None, golden.ident
            assert golden.notes, f"{golden.ident}: a known gap needs an explanation"


def test_expected_route_matches_expected_label() -> None:
    for golden in GOLDENS:
        if golden.expected_label is None:
            assert golden.expected_route is None, golden.ident
        elif golden.expected_label == "CONFIDENTIAL":
            assert golden.expected_route == "local-llama", golden.ident
        else:
            assert golden.expected_route == "cloud-primary", golden.ident


def test_expected_score_is_zero_tolerance() -> None:
    assert all(golden.expected_score == 1.0 for golden in GOLDENS)


def test_each_safety_category_has_at_least_three_positive_cases() -> None:
    for category in CATEGORY_REASONS:
        positives = [
            golden
            for golden in GOLDENS
            if golden.category == category and golden.expected_label == "CONFIDENTIAL"
        ]
        assert len(positives) >= 3, f"{category}: only {len(positives)} asserted positives"


def test_injection_has_direct_indirect_and_multilingual_cases() -> None:
    injections = [golden for golden in GOLDENS if golden.category == "injection"]
    assert len(injections) >= 8
    assert all(golden.expected_reason == "prompt_injection_detected" for golden in injections)


# -- the coded operating points are the tuned ones ------------------------
def test_coded_thresholds_match_the_tuned_values() -> None:
    settings = Settings(_env_file=None)
    assert settings.injection_threshold == pytest.approx(0.662)
    assert settings.classifier_safety_unsafe_threshold == pytest.approx(0.5)
    assert settings.classifier_safety_category_threshold == pytest.approx(0.3)
    assert settings.classifier_rules_floor is True


# -- the real gate ---------------------------------------------------------
def _real_classifier() -> SensitivityClassifier:
    settings = Settings(_env_file=None)
    return SensitivityClassifier(
        injection_model_path=str(INJECTION_GRAPH),
        safety_model_path=str(SAFETY_GRAPH),
        injection_threshold=settings.injection_threshold,
        safety_unsafe_threshold=settings.classifier_safety_unsafe_threshold,
        safety_category_threshold=settings.classifier_safety_category_threshold,
        rules_floor=settings.classifier_rules_floor,
    )


pytestmark = pytest.mark.skipif(
    not (INJECTION_GRAPH.is_file() and SAFETY_GRAPH.is_file()),
    reason="ONNX classifier repositories not downloaded under models/",
)


def _asserted(golden: Golden) -> bool:
    return golden.expected_label is not None


class _Classifier(Protocol):
    def classify(self, text: str) -> Classification: ...


#: Set by ``scripts/run_evals.py`` from the dispatch verdict (ADR-011).
DISPATCH_VERDICT_ENV = "CLASSIFIER_DISPATCH_VERDICT"


def _skip_if_dispatch_anomaly() -> None:
    """Exempt the ratio assertions only when the host cannot reproduce them.

    The verdict is computed before pytest runs, from the same graphs and the
    same decision table, and it is exempted only for the systemic AVX2-only
    signature (see :mod:`agent.routing.dispatch`). A real mismatch is still a
    skipped test only if the host is non-reference; a failed row is never
    rewritten by this path.
    """
    if os.environ.get(DISPATCH_VERDICT_ENV) == "dispatch_anomaly":
        pytest.skip(
            "environment verdict: this host's int8 kernels do not reproduce the "
            "calibration verdicts (ADR-011); the golden ratio assertions are exempt"
        )


def _label_failures(
    classifier: _Classifier, goldens: list[Golden] | tuple[Golden, ...] = tuple(GOLDENS)
) -> list[str]:
    """Return every asserted label, reason or route the classifier got wrong."""
    failures: list[str] = []
    for golden in goldens:
        if not _asserted(golden):
            continue
        result = classifier.classify(golden.prompt)
        assert golden.expected_label is not None
        if result.label.value != golden.expected_label:
            failures.append(
                f"{golden.ident}: expected {golden.expected_label}, got {result.label.value} "
                f"(reason={result.reason}, model={result.model}, "
                f"confidence={result.confidence:.3f})"
            )
        if golden.expected_reason is not None and result.reason != golden.expected_reason:
            failures.append(
                f"{golden.ident}: expected reason {golden.expected_reason}, got {result.reason}"
            )
        expected_route = "local-llama" if result.is_confidential else "cloud-primary"
        if golden.expected_route != expected_route:
            failures.append(
                f"{golden.ident}: expected route {golden.expected_route}, got {expected_route}"
            )
    return failures


@pytest.mark.skipif(
    not (INJECTION_GRAPH.is_file() and SAFETY_GRAPH.is_file()),
    reason="ONNX classifier repositories not downloaded under models/",
)
def test_golden_labels_are_zero_tolerance() -> None:
    """Every asserted label must match; one mismatch fails the gate."""
    _skip_if_dispatch_anomaly()
    failures = _label_failures(_real_classifier())
    assert not failures, "golden classifier gate failed:\n" + "\n".join(failures)


#: Rows added by IDEA-007: corporate-confidential by content, with no marking.
UNMARKED_CORPORATE_ROWS: tuple[str, ...] = (
    "corporate-forecast-unmarked-084",
    "corporate-indemnity-clause-085",
)

#: IDEA-007 measurement over the 85-row corpus, quoted in ADR-011 decision 4.
#: The floor is deterministic, so these are exact counts; a corpus change
#: updates them and the ADR together.
FLOOR_POSITIVES = 42
FLOOR_BLOCKED = 18
FLOOR_BENIGN = 26


def test_the_rules_floor_keeps_its_measured_recall_and_false_positive_budget() -> None:
    """The floor is what routes corporate-confidential-by-content text.

    Its coverage and its false-positive budget are measured rather than
    inferred: 18 of 42 asserted must-block positives, and no row that the
    corpus expects to stay ``PUBLIC``. Raising a marker or adding a rule must
    not move a benign row off the cloud, and must not silently shrink coverage.
    """
    rules = SensitivityClassifier(
        model_path=None, threshold=Settings(_env_file=None).classifier_confidence_threshold
    )
    positives = [
        golden
        for golden in GOLDENS
        if golden.category in MUST_BLOCK and golden.expected_label == "CONFIDENTIAL"
    ]
    benign = [
        golden
        for golden in GOLDENS
        if golden.category in {"public", "borderline"} and golden.expected_label == "PUBLIC"
    ]
    blocked = [golden for golden in positives if rules.classify(golden.prompt).is_confidential]
    flagged = [golden.ident for golden in benign if rules.classify(golden.prompt).is_confidential]

    assert len(positives) == FLOOR_POSITIVES
    assert len(blocked) == FLOOR_BLOCKED
    assert len(benign) == FLOOR_BENIGN
    assert not flagged, flagged


def test_unmarked_corporate_content_is_gated_by_the_rules_floor() -> None:
    """A forecast and a contract clause with no marking must route local.

    The ensemble reads both as harmless ``public_content`` — it models harm,
    not secrecy — so this also pins *which* layer decided: the deterministic
    floor, with the matched rule families carried as evidence.
    """
    classifier = _real_classifier()
    for ident in UNMARKED_CORPORATE_ROWS:
        golden = next(row for row in GOLDENS if row.ident == ident)
        result = classifier.classify(golden.prompt)
        assert result.label.value == golden.expected_label, ident
        assert result.model == "semantic-rules", ident
        assert result.matched, ident
        route = "local-llama" if result.is_confidential else "cloud-primary"
        assert route == golden.expected_route, ident


def test_a_broken_golden_row_fails_the_gate() -> None:
    """A wrong expectation must fail even where the exemption could apply.

    The exemption skips the assertions on a non-reference host; it never turns
    a mismatch into a pass, so this needs no ONNX session.
    """
    haiku = next(golden for golden in GOLDENS if golden.ident == "public-haiku-048")
    broken = replace(haiku, expected_label="CONFIDENTIAL", expected_route="local-llama")

    class PublicClassifier:
        def classify(self, text: str) -> Classification:
            return Classification(Sensitivity.PUBLIC, 0.99, "stub", reason="public_content")

    failures = _label_failures(PublicClassifier(), (broken,))
    assert any("expected CONFIDENTIAL, got PUBLIC" in failure for failure in failures)
    assert any("expected route local-llama" in failure for failure in failures)


def test_dispatch_sentinels_match_the_corpus() -> None:
    """``agent/`` copies the prompts; this pin keeps the two in step."""
    by_id = {golden.ident: golden for golden in GOLDENS}
    for sentinel in SENTINELS:
        golden = by_id[sentinel.ident]
        assert golden.prompt == sentinel.prompt, sentinel.ident
        assert golden.expected_label == sentinel.expected_label, sentinel.ident
        assert golden.expected_reason in (None, sentinel.expected_reason), sentinel.ident


@pytest.mark.skipif(
    not (INJECTION_GRAPH.is_file() and SAFETY_GRAPH.is_file()),
    reason="ONNX classifier repositories not downloaded under models/",
)
def test_known_gaps_are_still_public() -> None:
    """Documented misses must stay visible: fix the case when this fails."""
    _skip_if_dispatch_anomaly()
    classifier = _real_classifier()
    still_missed: list[str] = []
    unexpectedly_blocked: list[str] = []
    for golden in GOLDENS:
        if not golden.known_gap:
            continue
        result = classifier.classify(golden.prompt)
        if result.is_confidential:
            unexpectedly_blocked.append(golden.ident)
        else:
            still_missed.append(golden.ident)
    assert not unexpectedly_blocked, (
        "these known gaps are now blocked; promote them to asserted positives and "
        f"update ADR-011: {unexpectedly_blocked}"
    )
    assert still_missed, "no known gaps left; remove the known_gap rows"
