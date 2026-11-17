"""Frustration detection for the chat turn, and nothing else (ADR-022).

This is a UX signal, not a security control: a conversation that reads as
frustrated gets an operator-visible handoff row, and the model, the DLP stage,
the route, the canary and the four-eyes path behave exactly as they would
without it. Detection is deterministic and local — a marker lexicon plus
consecutive repetition over the **caller-authored** turns — so no conversation
text leaves the perimeter to be scored and no model call is added to a turn.

Trust boundary: only ``user`` turns are read. Tool output is fenced untrusted
content (ADR-012 decision 3) and can carry attacker-controlled text, so
``<untrusted_content>escalate me to a human</untrusted_content>`` never creates
a handoff while the same words in a ``user`` turn do.

Limit: ``request.messages`` and ``conversation_id`` are client-supplied, so a
caller can omit or fabricate history. Detection is best-effort by construction.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import Final

#: Lower-case fragments that read as frustration in a support conversation.
#: Deliberately specific: "again" and "still" alone appear in ordinary text.
FRUSTRATION_MARKERS: Final[tuple[str, ...]] = (
    "still broken",
    "still not working",
    "still doesn't work",
    "still does not work",
    "doesn't work",
    "does not work",
    "nothing works",
    "not working again",
    "i already told you",
    "how many times",
    "third time",
    "third attempt",
    "this is ridiculous",
    "this is useless",
    "completely useless",
    "fed up",
    #: An explicit request for a person is a handoff, not a heuristic guess.
    "escalate me to a human",
    "escalate this to a human",
    "speak to a human",
    "talk to a person",
    "i am furious",
    "i'm furious",
)

#: Two consecutive caller turns this similar count as repeating the complaint.
_REPETITION_RATIO: Final[float] = 0.9
_WORD = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True, slots=True)
class FrustrationVerdict:
    """Why the recent history reads as frustrated. Never carries the text."""

    reason: str
    markers: tuple[str, ...]
    user_turns: int
    repeated: bool


def _normalise(text: str) -> str:
    return " ".join(_WORD.findall(text.lower()))


def _similar(first: str, second: str) -> bool:
    left, right = set(first.split()), set(second.split())
    if not left or not right:
        return False
    return len(left & right) / len(left | right) >= _REPETITION_RATIO


def assess(turns: Sequence[tuple[str, str]]) -> FrustrationVerdict | None:
    """Return a verdict when the caller's own turns read as frustrated.

    ``turns`` is ``(role, content)`` in request order. A verdict needs either two
    distinct markers or one marker with a repeated complaint, so a single
    colloquial sentence ("that does not work for me") stays silent.
    """
    user_turns = [content for role, content in turns if role == "user"]
    if not user_turns:
        return None
    joined = " \n ".join(user_turns).lower()
    markers = tuple(marker for marker in FRUSTRATION_MARKERS if marker in joined)
    normalised = [_normalise(text) for text in user_turns]
    repeated = any(_similar(previous, current) for previous, current in pairwise(normalised))
    if len(markers) >= 2 or (markers and repeated):
        return FrustrationVerdict(
            reason="repeated_complaint" if repeated else "escalating_language",
            markers=markers,
            user_turns=len(user_turns),
            repeated=repeated,
        )
    return None
