"""Instruction-shape markers for the short-prompt injection decision.

ADR-011 decision 3: on a prompt of a few tokens the guard scores a benign
imperative ("say OK", "just escalate") as high as a short jailbreak, so a high
score there is only evidence of an override or a prompt-extraction attempt when
the text has one of the shapes below. Deliberately narrow — an override target,
a system-prompt extraction verb, a "repeat ... exactly" shape, or a jailbreak
persona — and measured against the corpus in ``tests/test_injection_short.py``.
"""

from __future__ import annotations

import re
from typing import Final

_MARKERS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}"
        r"\b(?:instructions?|rules?|prompts?|directions?|guidelines?|operator)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:reveal|print|show|output|display|leak|dump|repeat)\b[^.\n]{0,40}"
        r"\b(?:system|hidden|initial|internal|secret)\s+(?:prompt|instructions?)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\brepeat\b[^.\n]{0,30}\bexactly\b", re.IGNORECASE),
    re.compile(
        r"\b(?:you are|act as|pretend to be|roleplay as)\b[^.\n]{0,40}"
        r"\b(?:dan|unrestricted|jailbroken|unfiltered|no rules"
        r"|without (?:any )?(?:rules|restrictions|limits))\b",
        re.IGNORECASE,
    ),
)


def instruction_marker(text: str) -> bool:
    """True when ``text`` carries an override or prompt-extraction shape."""
    return any(pattern.search(text) for pattern in _MARKERS)
