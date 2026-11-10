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

from pathlib import Path

import pytest

from agent.routing.classifier import (
    CATEGORY_REASONS,
    SensitivityClassifier,
)
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


@pytest.mark.skipif(
    not (INJECTION_GRAPH.is_file() and SAFETY_GRAPH.is_file()),
    reason="ONNX classifier repositories not downloaded under models/",
)
def test_golden_labels_are_zero_tolerance() -> None:
    """Every asserted label must match; one mismatch fails the gate."""
    classifier = _real_classifier()
    failures: list[str] = []
    for golden in GOLDENS:
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
    assert not failures, "golden classifier gate failed:\n" + "\n".join(failures)


@pytest.mark.skipif(
    not (INJECTION_GRAPH.is_file() and SAFETY_GRAPH.is_file()),
    reason="ONNX classifier repositories not downloaded under models/",
)
def test_known_gaps_are_still_public() -> None:
    """Documented misses must stay visible: fix the case when this fails."""
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
