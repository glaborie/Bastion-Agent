"""Build the guardrails before the first request (ADR-011, IDEA-067).

The DLP analyzer (Presidio plus the spaCy pipelines) and the ONNX ensemble are
expensive to construct and were built lazily by whichever request arrived first,
so the first chat turn after a restart paid several seconds that every later
turn did not. Both processes now build them during startup, through the same
accessors the request path uses, so there is exactly one instance and a failure
is a startup failure rather than a first-request 500. Construction alone was not
enough: the first inference through each guard paid a further 1.4 s, so warm-up
runs one language detection, one analysis and one classification over a
fixed warm-up string.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Final

from agent.dlp.presidio import detect_language, get_analyzer
from agent.routing.classifier import get_classifier

logger = logging.getLogger(__name__)

#: A fixed, content-free string: warm-up must not need a caller's prompt. It has
#: to be long enough to detect as English — "warm up" detects as Swahili, and the
#: analyzer refuses an unmodelled language.
_WARMUP_TEXT: Final[str] = "The quick brown fox jumps over the lazy dog."


def _warm_dlp() -> None:
    """Build the analyzer and pay the spaCy pipeline's first-document cost.

    Constructing the engine is not enough: the first ``analyze`` call is what
    initialises the nlp pipeline's token vectors, and that was the 1.4 s the
    first request still paid after the engine was preloaded.
    """
    # The stage detects the prompt's language before it analyses it, and the
    # first ``langdetect`` call loads its profiles (measured 319 ms). Only
    # English has an NER model here (``_SPACY_MODELS``), so English is the
    # pipeline to warm; other languages use the pattern recognizers.
    detect_language(_WARMUP_TEXT)
    get_analyzer().analyze(text=_WARMUP_TEXT, language="en")


def _warm_classifier() -> None:
    """Build both ONNX sessions and run one inference through each."""
    get_classifier().classify(_WARMUP_TEXT)


#: Guards in warm order, as ``(name, build)`` pairs.
GUARDS: Final[tuple[tuple[str, Callable[[], Any]], ...]] = (
    ("dlp", _warm_dlp),
    ("classifier", _warm_classifier),
)

_warm = False


class GuardWarmUpError(RuntimeError):
    """A guardrail could not be built, so this process must not serve traffic."""


def warm_guards() -> None:
    """Construct every guardrail once; raise :class:`GuardWarmUpError` on failure."""
    global _warm  # pylint: disable=global-statement
    _warm = False
    for name, build in GUARDS:
        try:
            build()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # The exception type is enough to triage: the message may carry a
            # model path or a provider error, never request content.
            logger.error(
                "Guardrail warm-up failed",
                extra={"guard": name, "error": type(exc).__name__},
            )
            raise GuardWarmUpError(f"{name} warm-up failed: {type(exc).__name__}") from exc
    _warm = True
    logger.info("Guardrails warm", extra={"guards": ",".join(name for name, _ in GUARDS)})


def guards_are_warm() -> bool:
    """True once :func:`warm_guards` has built every guardrail in this process."""
    return _warm
