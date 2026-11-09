"""Deterministic DLP stage: Presidio entity detection + reversible redaction.

Presidio finds PII and secrets; this module replaces every accepted span with a
stable vault marker. Presidio's ``AnonymizerEngine`` replaces per entity type,
not per span, so tokenisation is performed here after analysis to give each
distinct value a stable, reversible marker. It never logs, returns or persists
the raw matched value — ``RedactionResult`` carries only the redacted text and
token metadata.

Initialisation is deliberately fail-closed: if Presidio or its spaCy model
cannot load, :class:`DLPUnavailableError` is raised instead of silently passing
unredacted text to a model.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from anyio import to_thread

from agent.dlp.vault import TokenVault, get_vault
from settings import get_settings

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, RecognizerResult

logger = logging.getLogger(__name__)

_SPACY_MODEL: Final[str] = "en_core_web_sm"

#: Provider token formats that Presidio does not ship a recognizer for.
_PROVIDER_TOKEN_PATTERN: Final[str] = (
    r"\b(?:"
    r"sk-(?:or-v1-)?[A-Za-z0-9_-]{16,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r")\b"
)

#: Generic assignments such as ``api_key = "..."`` / ``client_secret: ...``.
#: The whole assignment is redacted, which is safer than leaking its name/value
#: boundary and keeps the pattern compatible with Presidio's span model.
_GENERIC_SECRET_PATTERN: Final[str] = (
    r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret|password)"
    r"\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+]{12,}['\"]?"
)


class DLPUnavailableError(RuntimeError):
    """The deterministic DLP engine could not be initialised."""


@dataclass(frozen=True, slots=True)
class RedactionEntity:
    """Token metadata for one redacted span (never the matched value)."""

    token: str
    entity_type: str
    start: int
    end: int
    score: float


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """Result of one redaction pass."""

    text: str
    entities: tuple[RedactionEntity, ...] = ()

    @property
    def redacted(self) -> bool:
        return bool(self.entities)

    @property
    def entity_types(self) -> tuple[str, ...]:
        return tuple(entity.entity_type for entity in self.entities)

    def __bool__(self) -> bool:
        return self.redacted


def _api_key_recognizer() -> PatternRecognizer:
    from presidio_analyzer import Pattern, PatternRecognizer

    return PatternRecognizer(
        supported_entity="API_KEY",
        supported_language="en",
        patterns=[
            Pattern(name="provider-token", regex=_PROVIDER_TOKEN_PATTERN, score=0.9),
            Pattern(name="secret-assignment", regex=_GENERIC_SECRET_PATTERN, score=0.75),
        ],
    )


@functools.lru_cache(maxsize=1)
def get_analyzer() -> AnalyzerEngine:
    """Load and cache the Presidio analyzer (spaCy small model)."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    try:
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": _SPACY_MODEL}],
            }
        )
        analyzer = AnalyzerEngine(
            nlp_engine=provider.create_engine(),
            supported_languages=["en"],
        )
        analyzer.registry.add_recognizer(_api_key_recognizer())
    except Exception as exc:  # pragma: no cover - depends on the runtime image
        raise DLPUnavailableError(
            "Presidio could not be initialised; refusing to pass text unredacted"
        ) from exc
    logger.info("Presidio analyzer ready", extra={"spacy_model": _SPACY_MODEL})
    return analyzer


class PresidioDLP:
    """Deterministic entity scrubber with reversible vault markers."""

    def __init__(
        self,
        vault: TokenVault,
        *,
        analyzer: AnalyzerEngine | None = None,
        entities: Sequence[str] | None = None,
        score_threshold: float | None = None,
    ) -> None:
        settings = get_settings()
        self._vault = vault
        self._analyzer = analyzer
        self._entities = tuple(entities) if entities is not None else settings.dlp_entity_list
        if not self._entities:
            raise ValueError("at least one DLP entity type is required")
        self._threshold = (
            settings.dlp_score_threshold if score_threshold is None else score_threshold
        )
        if not 0.0 <= self._threshold <= 1.0:
            raise ValueError("score_threshold must be within [0.0, 1.0]")

    def _engine(self) -> AnalyzerEngine:
        return self._analyzer if self._analyzer is not None else get_analyzer()

    def analyze(self, text: str) -> list[RecognizerResult]:
        """Run Presidio synchronously (use :meth:`redact` from async code)."""
        if not text:
            return []
        return self._engine().analyze(
            text=text,
            language="en",
            entities=list(self._entities),
            score_threshold=self._threshold,
        )

    async def redact(self, text: str, session_id: str) -> RedactionResult:
        """Replace sensitive spans with session-scoped vault markers."""
        if not text:
            return RedactionResult(text="")
        results = await to_thread.run_sync(self.analyze, text)
        spans = _select_non_overlapping(results, text_length=len(text))
        if not spans:
            return RedactionResult(text=text)

        pieces: list[str] = []
        entities: list[RedactionEntity] = []
        cursor = 0
        for result in spans:
            token = await self._vault.get_or_create(
                session_id,
                result.entity_type,
                text[result.start : result.end],
            )
            pieces.append(text[cursor : result.start])
            pieces.append(token)
            entities.append(
                RedactionEntity(
                    token=token,
                    entity_type=result.entity_type,
                    start=result.start,
                    end=result.end,
                    score=float(result.score),
                )
            )
            cursor = result.end
        pieces.append(text[cursor:])

        logger.info(
            "DLP redaction applied",
            extra={"entities": len(entities), "types": sorted({e.entity_type for e in entities})},
        )
        return RedactionResult(text="".join(pieces), entities=tuple(entities))

    async def restore(self, text: str, session_id: str) -> str:
        """Restore known markers for an authorised recipient."""
        return await self._vault.restore(session_id, text)


def _select_non_overlapping(
    results: Sequence[RecognizerResult], *, text_length: int
) -> list[RecognizerResult]:
    """Keep the highest-scoring, longest span when Presidio results overlap."""
    valid = [result for result in results if 0 <= result.start < result.end <= text_length]
    ordered = sorted(valid, key=lambda result: (result.start, -result.score, -result.end))
    selected: list[RecognizerResult] = []
    last_end = 0
    for result in ordered:
        if result.start >= last_end:
            selected.append(result)
            last_end = result.end
    return selected


@functools.lru_cache(maxsize=1)
def get_dlp() -> PresidioDLP:
    """Process-wide DLP engine wired to the shared vault."""
    return PresidioDLP(get_vault())
