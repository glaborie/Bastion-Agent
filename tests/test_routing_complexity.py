"""Complexity tiering tests (ADR-004 decision 3).

Complexity only chooses between cloud tiers. The properties pinned here are the
ones that keep it from becoming a routing hazard: the signal is deterministic,
the threshold is the single control, a CONFIDENTIAL or PII-bearing prompt never
moves off the local alias, the labels are never rewritten, and the OmniRoute
contract carries the alias the router actually sends.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import yaml

from agent.routing.classifier import Classification, Sensitivity, SensitivityClassifier
from agent.routing.client import ModelRouter, OmniRouteClient
from agent.routing.complexity import (
    LENGTH_CEILING_WORDS,
    ComplexityTier,
    assess_complexity,
)
from settings import get_settings

SIMPLE_PROMPTS = (
    "What is the capital of France?",
    "Summarise this line: the invoice is overdue.",
    "Translate 'good morning' into German.",
    "What time does the build usually finish?",
)

COMPLEX_PROMPTS = (
    "Analyze the three proposals, compare their trade-offs, then recommend one.",
    (
        "Step by step: design a migration plan for the billing tables.\n"
        "1. inventory the columns\n"
        "2. write the backfill"
    ),
    "Debug this failing job:\n```\nTimeoutError\n```\nIt fails every ten minutes.",
    "Why did latency double after the deploy? Which component owns the retry?"
    " Compare the two dashboards first.",
)


class StubClassifier:
    """Classifier double: the complexity signal under test is the real one."""

    def __init__(self, classification: Classification) -> None:
        self.classification = classification

    def classify(self, text: str) -> Classification:
        return self.classification

    async def aclassify(self, text: str) -> Classification:
        return self.classification


def public() -> Classification:
    return Classification(Sensitivity.PUBLIC, 0.1, "semantic-rules")


def confidential() -> Classification:
    return Classification(Sensitivity.CONFIDENTIAL, 0.9, "semantic-rules")


def router(classification: Classification) -> ModelRouter:
    return ModelRouter(
        cast(SensitivityClassifier, StubClassifier(classification)),
        cast(OmniRouteClient, None),
    )


@pytest.mark.parametrize("prompt", SIMPLE_PROMPTS)
async def test_simple_prompts_route_to_the_cheap_alias(prompt: str) -> None:
    settings = get_settings()
    decision = await router(public()).aroute(prompt)

    assert decision.alias == settings.model_cloud_alias
    assert decision.primary_model == settings.model_cloud_primary
    assert decision.local is False
    assert decision.complexity is not None
    assert decision.complexity.tier is ComplexityTier.SIMPLE


@pytest.mark.parametrize("prompt", COMPLEX_PROMPTS)
async def test_hard_prompts_route_to_the_strong_alias(prompt: str) -> None:
    settings = get_settings()
    decision = router(public()).route(prompt)

    assert decision.alias == settings.model_cloud_strong_alias
    assert decision.primary_model == settings.model_cloud_strong_primary
    assert decision.local is False
    assert decision.override is None
    assert decision.complexity is not None
    assert decision.complexity.tier is ComplexityTier.COMPLEX


@pytest.mark.parametrize("prompt", COMPLEX_PROMPTS)
def test_confidentiality_wins_over_complexity(prompt: str) -> None:
    """A hard CONFIDENTIAL prompt stays local, and its label is not rewritten."""
    decision = router(confidential()).route(prompt)

    assert decision.alias == get_settings().model_local_alias
    assert decision.local is True
    assert decision.override is None
    assert decision.classification.label is Sensitivity.CONFIDENTIAL
    # The verdict is still recorded: it explains the tier the cloud may have used.
    assert decision.complexity is not None
    assert decision.complexity.tier is ComplexityTier.COMPLEX


@pytest.mark.parametrize("prompt", COMPLEX_PROMPTS)
async def test_a_dlp_hit_keeps_a_hard_prompt_local(prompt: str) -> None:
    """ADR-002 decision 5: the label stays PUBLIC, the route stays local."""
    decision = await router(public()).aroute(prompt, pii_detected=True)

    assert decision.alias == get_settings().model_local_alias
    assert decision.local is True
    assert decision.override == "pii_detected"
    assert decision.classification.label is Sensitivity.PUBLIC


def test_the_signal_is_deterministic_and_bounded() -> None:
    prompt = COMPLEX_PROMPTS[0]

    first = assess_complexity(prompt)
    assert first == assess_complexity(prompt)
    assert 0.0 <= first.score <= 1.0
    assert first.matched == ("analysis_verb", "trade_offs")
    assert assess_complexity(SIMPLE_PROMPTS[0]).score == 0.0


def test_length_alone_does_not_make_a_prompt_hard() -> None:
    """A long pasted document is cheap traffic; only markers or work are hard."""
    pasted = " ".join(["clause"] * (LENGTH_CEILING_WORDS + 40))

    result = assess_complexity(pasted)

    assert result.tier is ComplexityTier.SIMPLE
    assert result.score < get_settings().complexity_threshold


def test_the_threshold_is_the_single_tier_control() -> None:
    prompt = "Design a caching layer for the API."

    assert assess_complexity(prompt).tier is ComplexityTier.SIMPLE
    assert assess_complexity(prompt, threshold=0.3).tier is ComplexityTier.COMPLEX


def test_the_tiering_is_configurable_through_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    from settings import reset_settings_cache

    monkeypatch.setenv("COMPLEXITY_THRESHOLD", "1.0")
    reset_settings_cache()
    try:
        assert assess_complexity(COMPLEX_PROMPTS[0]).tier is ComplexityTier.SIMPLE
        assert router(public()).route(COMPLEX_PROMPTS[0]).alias == "cloud-primary"
    finally:
        monkeypatch.delenv("COMPLEXITY_THRESHOLD")
        reset_settings_cache()


def test_the_strong_alias_mirrors_the_omniroute_combos() -> None:
    """A tier the router can name but OmniRoute cannot resolve is dead traffic."""
    from scripts.omniroute_bootstrap import COMBOS

    config = yaml.safe_load(Path("config/omniroute/config.yaml").read_text(encoding="utf-8"))
    combos = config["combos"]
    settings = get_settings()

    for alias, pinned in (
        ("local-llama", settings.model_local_primary),
        ("cloud-primary", settings.model_cloud_primary),
        (settings.model_cloud_strong_alias, settings.model_cloud_strong_primary),
    ):
        first_target = combos[alias]["models"][0]
        assert first_target.split("/", 1)[1] == pinned, (alias, first_target, pinned)

    assert combos.keys() == COMBOS.keys()
    for name, spec in COMBOS.items():
        assert combos[name]["strategy"] == spec["strategy"], name
        assert combos[name]["models"] == spec["models"], name
