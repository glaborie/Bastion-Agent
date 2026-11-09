"""Sensitivity classifier tests (ADR-004)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from agent.routing.classifier import (
    ClassifierConfigurationError,
    Sensitivity,
    SensitivityClassifier,
    _softmax,
)


def classifier(threshold: float = 0.55) -> SensitivityClassifier:
    return SensitivityClassifier(model_path=None, threshold=threshold)


def test_general_prompt_is_public() -> None:
    result = classifier().classify("Write a haiku about the sea.")
    assert result.label is Sensitivity.PUBLIC
    assert result.confidence == 0.0
    assert result.model == "semantic-rules"
    assert not result.matched


def test_explicit_confidential_marking_crosses_the_default_threshold() -> None:
    result = classifier().classify("This document is strictly confidential.")
    assert result.label is Sensitivity.CONFIDENTIAL
    assert result.confidence >= 0.55
    assert "explicit_marking" in result.matched


def test_internal_marking_is_confidential() -> None:
    result = classifier().classify("Internal only: the migration date is Friday.")
    assert result.label is Sensitivity.CONFIDENTIAL
    assert result.confidence == pytest.approx(0.6)


def test_a_single_codename_is_borderline_and_stays_public() -> None:
    result = classifier().classify("Project Nightingale launches next quarter.")
    assert result.confidence == pytest.approx(0.5)
    assert result.label is Sensitivity.PUBLIC
    assert result.matched == ("codename",)


def test_threshold_is_the_gate_not_the_marker() -> None:
    prompt = "Project Nightingale launches next quarter."
    assert classifier(threshold=0.45).classify(prompt).label is Sensitivity.CONFIDENTIAL
    assert classifier(threshold=0.55).classify(prompt).label is Sensitivity.PUBLIC


def test_combined_markers_cross_the_threshold() -> None:
    result = classifier().classify("Project Nightingale is internal only.")
    assert result.label is Sensitivity.CONFIDENTIAL
    assert result.confidence > 0.7
    assert set(result.matched) == {"codename", "internal_marking"}


@pytest.mark.parametrize(
    "prompt",
    [
        "The board meeting minutes are attached.",
        "Our compensation bands for this level.",
        "The customer list and pricing strategy.",
        "We are in due diligence for the acquisition.",
        "The source code repository layout.",
    ],
)
def test_confidential_domains_are_detected(prompt: str) -> None:
    assert classifier().classify(prompt).label is Sensitivity.CONFIDENTIAL


def test_empty_prompt_is_public() -> None:
    result = classifier().classify("   ")
    assert result.label is Sensitivity.PUBLIC
    assert result.confidence == 0.0


def test_reason_contains_families_not_the_prompt() -> None:
    prompt = "The term sheet and cap table are attached."
    result = classifier().classify(prompt)
    assert "corporate_finance" in result.reason
    assert "term sheet" not in result.reason


def test_missing_onnx_model_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ClassifierConfigurationError, match="model not found"):
        SensitivityClassifier(model_path=str(tmp_path / "missing.onnx"))


def test_missing_tokenizer_fails_closed(tmp_path: Path) -> None:
    model = tmp_path / "model.onnx"
    model.write_bytes(b"not-a-real-onnx-model")
    with pytest.raises(ClassifierConfigurationError, match="tokenizer not found"):
        SensitivityClassifier(model_path=str(model))


def test_softmax_is_stable_for_large_logits() -> None:
    probabilities = _softmax(np.array([1000.0, 999.0]))
    assert np.isfinite(probabilities).all()
    assert probabilities.sum() == pytest.approx(1.0)
    assert probabilities[0] > probabilities[1]


def test_invalid_threshold_is_rejected() -> None:
    with pytest.raises(ValueError, match="threshold"):
        SensitivityClassifier(model_path=None, threshold=1.5)
    with pytest.raises(ValueError, match="max_tokens"):
        SensitivityClassifier(model_path=None, max_tokens=0)
