"""Deterministic prompt-complexity signal for model tiering (ADR-004).

Complexity is a **cost and quality** signal, never a security one: it may only
choose among the models of the same confidentiality class, after the sensitivity
verdict has already decided that the cloud is allowed at all. It reads the same
raw text the sensitivity classifier reads, and it is derived from it alone, so
the same prompt always gets the same tier.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from settings import get_settings

#: Words below which the length component stays zero, and at which it saturates:
#: a long pasted document is not automatically hard work.
LENGTH_FLOOR_WORDS: Final[int] = 40
LENGTH_CEILING_WORDS: Final[int] = 160
#: Weights of the two components. Markers dominate because a short "compare A
#: with B, then recommend one" is real work, while a long prompt is only a hint.
MARKER_WEIGHT: Final[float] = 0.7
LENGTH_WEIGHT: Final[float] = 0.3
#: Two distinct markers (or one marker in a long prompt) reach the default 0.6.
MARKERS_FOR_FULL_SCORE: Final[int] = 2

#: Named markers; each counts once however often it occurs in the prompt.
_MARKERS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("step_by_step", re.compile(r"\bstep[- ]by[- ]step\b", re.IGNORECASE)),
    ("enumerated_items", re.compile(r"(?m)^\s*(?:\d+[.)]|[-*])\s+\S")),
    ("multi_question", re.compile(r"\?[\s\S]*\?")),
    ("code_block", re.compile(r"```")),
    (
        "analysis_verb",
        re.compile(
            r"\b(?:analyz|analys|compar|design|implement|refactor|debug|optimi[sz]"
            r"|deriv|prove|architect|migrat|benchmark|evaluat)",
            re.IGNORECASE,
        ),
    ),
    ("trade_offs", re.compile(r"\btrade[- ]?offs?\b|\bpros and cons\b", re.IGNORECASE)),
)


class ComplexityTier(StrEnum):
    """Which cloud tier a PUBLIC prompt belongs to."""

    SIMPLE = "simple"
    COMPLEX = "complex"


@dataclass(frozen=True, slots=True)
class Complexity:
    """The tier plus the evidence that selected it (never the prompt text)."""

    tier: ComplexityTier
    score: float
    threshold: float
    matched: tuple[str, ...] = ()


def assess_complexity(text: str, *, threshold: float | None = None) -> Complexity:
    """Score ``text`` and return its tier; ``threshold`` overrides the setting."""
    words = len(text.split())
    span = LENGTH_CEILING_WORDS - LENGTH_FLOOR_WORDS
    length = min(1.0, max(0.0, (words - LENGTH_FLOOR_WORDS) / span))
    matched = tuple(name for name, pattern in _MARKERS if pattern.search(text))
    markers = min(1.0, len(matched) / MARKERS_FOR_FULL_SCORE)
    score = round(MARKER_WEIGHT * markers + LENGTH_WEIGHT * length, 3)
    limit = get_settings().complexity_threshold if threshold is None else threshold
    tier = ComplexityTier.COMPLEX if score >= limit else ComplexityTier.SIMPLE
    return Complexity(tier=tier, score=score, threshold=limit, matched=matched)
