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

Language contract (ADR-002): only the languages in :data:`_SPACY_MODELS` have an
NER model here. A prompt detected as another language still runs the
language-independent pattern recognizers — email, IBAN, API key, credit card,
IP address, phone number, US SSN — but the NER-backed entities are skipped
rather than handed to the English model, which tagged ``"donne moi le "`` as a
person and corrupted the prompt. Below the configured detector confidence the
text is analyzed as English, so a short English prompt keeps full NER coverage.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from anyio import to_thread
from langdetect import DetectorFactory, LangDetectException, detect_langs

from agent.dlp.vault import TokenVault, get_vault
from settings import get_settings

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, RecognizerResult

logger = logging.getLogger(__name__)

#: ``langdetect`` resolves ties from a profiled distribution; a fixed seed makes
#: the same prompt produce the same language on every host and every run.
DetectorFactory.seed = 0

#: Languages with an NER model in this image. Adding one means adding its spaCy
#: package to ``pyproject.toml`` and the image, plus one entry here.
_SPACY_MODELS: Final[Mapping[str, str]] = MappingProxyType({"en": "en_core_web_sm"})
_SUPPORTED_LANGUAGES: Final[tuple[str, ...]] = tuple(_SPACY_MODELS)
_DEFAULT_LANGUAGE: Final[str] = "en"

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
    #: Detector verdict when it was usable, else the default language.
    language: str = _DEFAULT_LANGUAGE
    #: True when a non-English language was detected and the NER-backed
    #: entities were skipped; the pattern recognizers still ran.
    ner_skipped: bool = False

    @property
    def redacted(self) -> bool:
        return bool(self.entities)

    @property
    def entity_types(self) -> tuple[str, ...]:
        return tuple(entity.entity_type for entity in self.entities)

    def __bool__(self) -> bool:
        return self.redacted


@dataclass(frozen=True, slots=True)
class _LanguagePlan:
    """Which language Presidio is asked for and whether NER may run."""

    analyze_language: str
    detected: str
    confidence: float
    ner_skipped: bool


def detect_language(text: str) -> tuple[str, float]:
    """Return the most likely language and its probability, or ``("", 0.0)``.

    This is a routing hint for the DLP stage, not an authorization decision: a
    wrong answer can only skip the NER pass on text it reads as foreign, and the
    pattern recognizers are never gated on it.
    """
    try:
        candidates = detect_langs(text)
    except LangDetectException:
        return "", 0.0
    if not candidates:
        return "", 0.0
    top = candidates[0]
    return top.lang, float(top.prob)


def _api_key_recognizer(language: str = _DEFAULT_LANGUAGE) -> PatternRecognizer:
    from presidio_analyzer import Pattern, PatternRecognizer

    return PatternRecognizer(
        supported_entity="API_KEY",
        supported_language=language,
        patterns=[
            Pattern(name="provider-token", regex=_PROVIDER_TOKEN_PATTERN, score=0.9),
            Pattern(name="secret-assignment", regex=_GENERIC_SECRET_PATTERN, score=0.75),
        ],
    )


@functools.lru_cache(maxsize=1)
def get_analyzer() -> AnalyzerEngine:
    """Load and cache the Presidio analyzer for every modelled language."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    try:
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [
                    {"lang_code": language, "model_name": model}
                    for language, model in _SPACY_MODELS.items()
                ],
            }
        )
        analyzer = AnalyzerEngine(
            nlp_engine=provider.create_engine(),
            supported_languages=list(_SUPPORTED_LANGUAGES),
        )
        # One instance per modelled language: Presidio only runs a recognizer
        # for the language it declares, so a future second model would otherwise
        # silently lose API_KEY coverage.
        for language in _SUPPORTED_LANGUAGES:
            analyzer.registry.add_recognizer(_api_key_recognizer(language))
    except Exception as exc:  # pragma: no cover - depends on the runtime image
        raise DLPUnavailableError(
            "Presidio could not be initialised; refusing to pass text unredacted"
        ) from exc
    logger.info(
        "Presidio analyzer ready",
        extra={"languages": ",".join(_SUPPORTED_LANGUAGES)},
    )
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
        self._min_language_confidence = settings.dlp_language_min_confidence
        if not 0.0 <= self._min_language_confidence <= 1.0:
            raise ValueError("dlp_language_min_confidence must be within [0.0, 1.0]")

    def _engine(self) -> AnalyzerEngine:
        return self._analyzer if self._analyzer is not None else get_analyzer()

    def _plan(self, text: str) -> _LanguagePlan:
        """Decide the analysis language and whether the NER pass may run.

        Only a language with a loaded spaCy model gets NER. A confident
        non-English verdict skips it: the English model tagged
        ``"donne moi le "`` as a person, which corrupted the prompt and wrote a
        false ``DLP_REDACTION``. An inconclusive verdict stays on the default
        language, so short English prompts are not penalised.
        """
        detected, confidence = detect_language(text)
        if (
            detected
            and detected not in _SUPPORTED_LANGUAGES
            and confidence >= self._min_language_confidence
        ):
            return _LanguagePlan(
                analyze_language=_DEFAULT_LANGUAGE,
                detected=detected,
                confidence=confidence,
                ner_skipped=True,
            )
        analyze_language = detected if detected in _SUPPORTED_LANGUAGES else _DEFAULT_LANGUAGE
        return _LanguagePlan(
            analyze_language=analyze_language,
            detected=detected,
            confidence=confidence,
            ner_skipped=False,
        )

    def _pattern_entities(self, language: str) -> list[str]:
        """Configured entities supplied by regex recognizers rather than NER.

        Presidio's pattern recognizers do not parse the text's grammar, so they
        stay correct for every language; the NER-backed ones are the only ones
        a language mismatch can corrupt.
        """
        from presidio_analyzer import PatternRecognizer

        pattern_types: set[str] = set()
        for recognizer in self._engine().registry.get_recognizers(
            language=language, all_fields=True
        ):
            if isinstance(recognizer, PatternRecognizer):
                pattern_types.update(recognizer.supported_entities)
        return [entity for entity in self._entities if entity in pattern_types]

    def _analyze(self, text: str) -> tuple[list[RecognizerResult], _LanguagePlan]:
        plan = self._plan(text)
        if plan.ner_skipped:
            entities = self._pattern_entities(plan.analyze_language)
            logger.info(
                "DLP NER skipped for a language without a model",
                extra={
                    "language": plan.detected,
                    "confidence": round(plan.confidence, 2),
                    "entities": ",".join(entities),
                },
            )
            if not entities:
                return [], plan
        else:
            entities = list(self._entities)

        results = self._engine().analyze(
            text=text,
            language=plan.analyze_language,
            entities=entities,
            score_threshold=self._threshold,
        )
        return results, plan

    def analyze(self, text: str) -> list[RecognizerResult]:
        """Run Presidio synchronously (use :meth:`redact` from async code)."""
        if not text:
            return []
        return self._analyze(text)[0]

    async def redact(self, text: str, session_id: str) -> RedactionResult:
        """Replace sensitive spans with session-scoped vault markers."""
        if not text:
            return RedactionResult(text="")
        results, plan = await to_thread.run_sync(self._analyze, text)
        spans = _select_non_overlapping(results, text_length=len(text))
        language = plan.detected or _DEFAULT_LANGUAGE
        if not spans:
            return RedactionResult(text=text, language=language, ner_skipped=plan.ner_skipped)

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
        return RedactionResult(
            text="".join(pieces),
            entities=tuple(entities),
            language=language,
            ner_skipped=plan.ner_skipped,
        )

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
