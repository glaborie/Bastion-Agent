"""Two-stage confidentiality classifier (ADR-004).

A distilled sequence classifier can run locally through ONNX Runtime. When no
model is configured, a deterministic semantic-rule classifier provides the same
interface. Both return a confidence for the ``CONFIDENTIAL`` label; the caller
compares it with ``CLASSIFIER_CONFIDENCE_THRESHOLD``. Borderline prompts are
treated as PUBLIC by policy (cost trade-off), not as confidential.

ONNX contract: the graph takes ``input_ids`` (plus ``attention_mask`` and
optionally ``token_type_ids``) and returns two logits ordered
``[PUBLIC, CONFIDENTIAL]``. The tokenizer is a Hugging Face ``tokenizer.json``.
"""

from __future__ import annotations

import functools
import logging
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import numpy as np
from anyio import to_thread

from settings import get_settings

logger = logging.getLogger(__name__)


class ClassifierConfigurationError(RuntimeError):
    """The configured ONNX model or tokenizer is missing or unusable."""


class Sensitivity(StrEnum):
    PUBLIC = "PUBLIC"
    CONFIDENTIAL = "CONFIDENTIAL"


@dataclass(frozen=True, slots=True)
class Classification:
    """A sensitivity decision with its evidence."""

    label: Sensitivity
    confidence: float
    model: str
    matched: tuple[str, ...] = ()
    reason: str = ""

    @property
    def is_confidential(self) -> bool:
        return self.label is Sensitivity.CONFIDENTIAL

    def __bool__(self) -> bool:
        return self.is_confidential


@dataclass(frozen=True, slots=True)
class _Rule:
    name: str
    weight: float
    pattern: re.Pattern[str]


#: Weighted semantic markers. A single weight-3/4 marker crosses the default
#: 0.55 threshold; a single weight-2 marker stays borderline (PUBLIC by policy).
_RULES: Final[tuple[_Rule, ...]] = (
    _Rule(
        "explicit_marking",
        4.0,
        re.compile(
            r"\b(?:strictly confidential|confidential|do not (?:share|distribute)|"
            r"proprietary|trade secret|need[- ]to[- ]know)\b",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "internal_marking",
        3.0,
        re.compile(
            r"\b(?:internal[- ]only|internal use|company[- ]confidential|"
            r"under nda|non[- ]disclosure)\b",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "codename",
        2.0,
        re.compile(
            r"\b(?i:project|codename|code name|initiative)\b\s+[\"']?[A-Z][A-Za-z0-9_-]{2,}"
        ),
    ),
    _Rule(
        "board_material",
        3.0,
        re.compile(
            r"\b(?:board (?:meeting|minutes|deck|memo)|executive committee|"
            r"leadership offsite)\b",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "corporate_finance",
        3.0,
        re.compile(
            r"\b(?:merger|acquisition|m&a|due diligence|term sheet|cap table|valuation)\b",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "hr_data",
        3.0,
        re.compile(
            r"\b(?:salary|compensation|bonus|equity grant|severance|performance review)\b",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "technical_ip",
        3.0,
        re.compile(
            r"\b(?:source code|repository|database schema|architecture|"
            r"private key|credentials)\b",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "customer_data",
        3.0,
        re.compile(r"\b(?:customer list|pricing strategy|customer churn)\b", re.IGNORECASE),
    ),
    _Rule(
        "commercial",
        2.0,
        re.compile(r"\b(?:sales pipeline|revenue forecast|margin analysis)\b", re.IGNORECASE),
    ),
    _Rule(
        "sensitive_personal",
        3.0,
        re.compile(
            r"\b(?:passport|social security|bank account|medical record|diagnosis)\b",
            re.IGNORECASE,
        ),
    ),
)

_RULE_MODEL: Final[str] = "semantic-rules"


class SensitivityClassifier:
    """ONNX sequence classifier with a deterministic semantic-rule fallback."""

    def __init__(
        self,
        *,
        model_path: str | None = None,
        tokenizer_path: str | None = None,
        max_tokens: int | None = None,
        threshold: float | None = None,
    ) -> None:
        settings = get_settings()
        self._model_path = Path(model_path).expanduser() if model_path else None
        self._tokenizer_path = Path(tokenizer_path).expanduser() if tokenizer_path else None
        self._max_tokens = settings.classifier_max_tokens if max_tokens is None else max_tokens
        self._threshold = (
            settings.classifier_confidence_threshold if threshold is None else threshold
        )
        if not 0.0 <= self._threshold <= 1.0:
            raise ValueError("threshold must be within [0.0, 1.0]")
        if self._max_tokens <= 0:
            raise ValueError("max_tokens must be positive")

        self._session: Any | None = None
        self._tokenizer: Any | None = None
        if self._model_path is not None:
            self._load_onnx()

    # -- public API -------------------------------------------------------
    def classify(self, text: str) -> Classification:
        """Classify a prompt (synchronous; use :meth:`aclassify` in async code)."""
        if self._session is not None:
            return self._classify_onnx(text)
        return self._classify_rules(text)

    async def aclassify(self, text: str) -> Classification:
        return await to_thread.run_sync(self.classify, text)

    @property
    def model_name(self) -> str:
        return self._model_path.name if self._model_path is not None else _RULE_MODEL

    # -- rule fallback ----------------------------------------------------
    def _classify_rules(self, text: str) -> Classification:
        if not text or not text.strip():
            return Classification(
                label=Sensitivity.PUBLIC,
                confidence=0.0,
                model=_RULE_MODEL,
                reason="empty prompt",
            )
        matched: list[str] = []
        total = 0.0
        for rule in _RULES:
            # pylint: disable-next=no-member  # astroid misreads re.Pattern[str]
            if rule.pattern.search(text):
                matched.append(rule.name)
                total += rule.weight

        # total / (total + 2): one weight-3 marker -> 0.60, one weight-2 -> 0.50,
        # two weight-3 markers -> 0.75. Capped below certainty.
        confidence = min(0.99, round(total / (total + 2.0), 4)) if total else 0.0
        label = Sensitivity.CONFIDENTIAL if confidence >= self._threshold else Sensitivity.PUBLIC
        return Classification(
            label=label,
            confidence=confidence,
            model=_RULE_MODEL,
            matched=tuple(sorted(matched)),
            reason="matched: " + ", ".join(sorted(matched)) if matched else "no markers",
        )

    # -- ONNX -------------------------------------------------------------
    def _load_onnx(self) -> None:
        if self._model_path is None:
            raise ClassifierConfigurationError("model path is not configured")
        if not self._model_path.is_file():
            raise ClassifierConfigurationError(f"classifier model not found: {self._model_path}")
        tokenizer_path = self._tokenizer_path or self._model_path.with_name("tokenizer.json")
        if not tokenizer_path.is_file():
            raise ClassifierConfigurationError(f"classifier tokenizer not found: {tokenizer_path}")
        try:
            import onnxruntime
            from tokenizers import Tokenizer
        except ImportError as exc:  # pragma: no cover - dependencies are pinned
            raise ClassifierConfigurationError(
                "onnxruntime and tokenizers are required for the ONNX classifier"
            ) from exc

        try:
            tokenizer = Tokenizer.from_file(str(tokenizer_path))
            tokenizer.enable_truncation(max_length=self._max_tokens)
            session = onnxruntime.InferenceSession(
                str(self._model_path),
                providers=["CPUExecutionProvider"],
            )
        except Exception as exc:
            raise ClassifierConfigurationError(
                f"could not load classifier artefacts from {self._model_path}"
            ) from exc

        self._tokenizer = tokenizer
        self._session = session
        logger.info(
            "ONNX sensitivity classifier ready",
            extra={"model": str(self._model_path), "max_tokens": self._max_tokens},
        )

    def _classify_onnx(self, text: str) -> Classification:
        if self._tokenizer is None or self._session is None:
            raise ClassifierConfigurationError("ONNX classifier is not loaded")
        encoding = self._tokenizer.encode(text or "")
        ids = list(encoding.ids)[: self._max_tokens]
        if not ids:
            ids = [0]
        feeds: dict[str, Any] = {}
        input_names = {item.name for item in self._session.get_inputs()}
        if "input_ids" not in input_names:
            raise ClassifierConfigurationError("ONNX model has no input_ids input")
        feeds["input_ids"] = np.array([ids], dtype=np.int64)
        if "attention_mask" in input_names:
            feeds["attention_mask"] = np.ones((1, len(ids)), dtype=np.int64)
        if "token_type_ids" in input_names:
            feeds["token_type_ids"] = np.zeros((1, len(ids)), dtype=np.int64)

        outputs = self._session.run(None, feeds)
        logits = np.asarray(outputs[0], dtype=np.float64).reshape(-1)
        if logits.size != 2:
            raise ClassifierConfigurationError(
                f"expected 2 output logits [PUBLIC, CONFIDENTIAL], got {logits.size}"
            )
        probabilities = _softmax(logits)
        confidential = float(probabilities[1])
        label = Sensitivity.CONFIDENTIAL if confidential >= self._threshold else Sensitivity.PUBLIC
        return Classification(
            label=label,
            confidence=round(confidential, 4),
            model=self.model_name,
            reason="onnx",
        )

    def __repr__(self) -> str:
        return f"SensitivityClassifier(model={self.model_name!r}, threshold={self._threshold})"


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - np.max(logits)
    exponentials = np.exp(shifted)
    return np.asarray(exponentials / np.sum(exponentials), dtype=np.float64)


@functools.lru_cache(maxsize=1)
def get_classifier() -> SensitivityClassifier:
    """Process-wide classifier from configuration."""
    settings = get_settings()
    return SensitivityClassifier(
        model_path=settings.classifier_model_path,
        tokenizer_path=settings.classifier_tokenizer_path,
        max_tokens=settings.classifier_max_tokens,
        threshold=settings.classifier_confidence_threshold,
    )
