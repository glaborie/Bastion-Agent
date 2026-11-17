"""Frustration detection for the chat turn, and nothing else (ADR-022).

This is a UX signal, not a security control: a conversation that reads as
frustrated gets an operator-visible handoff row, and the model, the DLP stage,
the route, the canary and the four-eyes path behave exactly as they would
without it. Detection is deterministic and local — a marker lexicon plus a
restatement check over the **caller-authored** turns — so no conversation text
leaves the perimeter to be scored and no model call is added to a turn.

The rule was calibrated on a labelled set of complaint and neutral transcripts
(``tests/data/frustration.jsonl``, 24 positives and 29 negatives) and measured
in ADR-022: 24/24 detected, 0/29 neutral conversations flagged. Every marker is
a *span*, so ``"still does not work"`` is one piece of evidence even though it
contains ``"does not work"`` — the defect that used to make one sentence fire
on its own.

Trust boundary: only ``user`` turns are read. Tool output is fenced untrusted
content (ADR-012 decision 3) and can carry attacker-controlled text, so
``<untrusted_content>escalate me to a human</untrusted_content>`` never creates
a handoff while the same words in a ``user`` turn do.

Limit: ``request.messages`` and ``conversation_id`` are client-supplied, so a
caller can omit or fabricate history. Detection is best-effort by construction,
and it is lexical: a complaint phrased entirely outside this vocabulary (and
without a restatement) stays silent.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import Final

#: Lower-case fragments that read as frustration in a support conversation.
#: Deliberately specific: "again" and "still" alone appear in ordinary text, so
#: they are always part of a longer phrase.
FRUSTRATION_MARKERS: Final[tuple[str, ...]] = (
    # The same failure, still there.
    "still not working",
    "still broken",
    "broken",
    "still doesn't work",
    "still does not work",
    "still not fixed",
    "not working again",
    "not working",
    "doesn't work",
    "does not work",
    "did not help",
    "didn't help",
    "doesn't help",
    "does not help",
    "not helping",
    "you are not helping",
    "nothing works",
    "nothing helps",
    "nothing has changed",
    "nothing was fixed",
    "not fixed",
    "not been fixed",
    "nobody has fixed",
    "no one is listening",
    "not listening",
    "keeps crashing",
    "crashed again",
    "keeps happening",
    "keep getting",
    "every time",
    # The complaint has moved from the product to the exchange.
    "i already told you",
    "how many times",
    "third time",
    "third attempt",
    "asked again",
    "again and again",
    "same problem",
    "same error",
    "why is this so hard",
    "why is this so difficult",
    "just fix",
    "never works",
    "getting nowhere",
    "gets nowhere",
    "nobody here can help",
    # Named affect.
    "i am furious",
    "i'm furious",
    "i am frustrated",
    "i'm frustrated",
    "frustrated",
    "frustrating",
    "frustration",
    "this is ridiculous",
    "this is useless",
    "completely useless",
    "waste of time",
    "waste of my time",
    "fed up",
    "sick of this",
    # An explicit request for a person is a handoff, not a heuristic guess.
    "escalate me to a human",
    "escalate this to a human",
    "speak to a human",
    "talk to a person",
    "i need a human",
)

#: Markers that are themselves a request for a human: they fire alone.
HANDOFF_MARKERS: Final[frozenset[str]] = frozenset(
    {
        "escalate me to a human",
        "escalate this to a human",
        "speak to a human",
        "talk to a person",
        "i need a human",
    }
)

#: Markers that are unambiguous on their own; the measured false-positive cost is
#: "frustrated" in the third person ("how should i handle a frustrated
#: customer?"), which is why that word is *not* here while "i am frustrated" is.
STRONG_MARKERS: Final[frozenset[str]] = frozenset(
    {
        "i am furious",
        "i'm furious",
        "i am frustrated",
        "i'm frustrated",
        "this is ridiculous",
        "this is useless",
        "completely useless",
        "nothing works",
        "i already told you",
        "how many times",
        "third time",
        "third attempt",
        "not listening",
        "waste of time",
        "waste of my time",
        "sick of this",
        "getting nowhere",
        "gets nowhere",
        "fed up",
    }
)

#: A restatement counts when most of the shorter turn's words reappear in the
#: longer one. Sets rather than Jaccard: a frustrated caller elaborates, so the
#: shared core is a small share of the union ("the button is not working" versus
#: "the button is not working, again" scores 1.0 here and 0.83 on Jaccard).
_REPETITION_CONTAINMENT: Final[float] = 0.7
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


def _markers(joined: str) -> tuple[str, ...]:
    """Distinct markers as non-overlapping spans, longest phrase first."""
    spans: list[tuple[int, int, str]] = []
    for marker in sorted(FRUSTRATION_MARKERS, key=len, reverse=True):
        start = joined.find(marker)
        while start != -1:
            end = start + len(marker)
            if all(end <= begin or start >= stop for begin, stop, _ in spans):
                spans.append((start, end, marker))
            start = joined.find(marker, start + 1)
    return tuple(dict.fromkeys(marker for _, _, marker in sorted(spans)))


def _repeated(normalised: Sequence[str]) -> bool:
    for previous, current in pairwise(normalised):
        left, right = set(previous.split()), set(current.split())
        if not left or not right:
            continue
        if len(left & right) / min(len(left), len(right)) >= _REPETITION_CONTAINMENT:
            return True
    return False


def assess(turns: Sequence[tuple[str, str]]) -> FrustrationVerdict | None:
    """Return a verdict when the caller's own turns read as frustrated.

    ``turns`` is ``(role, content)`` in request order. A verdict needs one of:
    a request for a human, a marker that is unambiguous on its own, two distinct
    markers, or one marker together with a restatement of the complaint. A single
    colloquial sentence ("that does not work for me") stays silent.
    """
    user_turns = [content for role, content in turns if role == "user"]
    if not user_turns:
        return None
    markers = _markers(" \n ".join(user_turns).lower())
    repeated = _repeated([_normalise(text) for text in user_turns])
    handoff = any(marker in HANDOFF_MARKERS for marker in markers)
    strong = any(marker in STRONG_MARKERS for marker in markers)
    if handoff or strong or len(markers) >= 2 or (markers and repeated):
        return FrustrationVerdict(
            reason="repeated_complaint" if repeated else "escalating_language",
            markers=markers,
            user_turns=len(user_turns),
            repeated=repeated,
        )
    return None
