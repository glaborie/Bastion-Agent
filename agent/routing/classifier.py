"""Two-stage confidentiality classifier (ADR-002, ADR-004, ADR-011).

The classifier answers one question for the router: may this prompt leave the
perimeter? Three implementations share the ``classify(text) -> Classification``
contract:

* **Ensemble** (ADR-011): an injection guard evaluated first, then a
  multi-label safety guard. This is the production gate. It can express two
  different risks — disclosure and manipulation — that a single sensitivity
  bit cannot.
* **Single graph** (legacy): one ONNX file returning two logits ordered
  ``[PUBLIC, CONFIDENTIAL]``.
* **Semantic rules**: a deterministic fallback for ``ENVIRONMENT=local`` only.
  It can never detect prompt injection, so a non-local deployment without a
  model fails at startup instead of silently degrading the gate.

Both ONNX models fail closed: a session error, a missing graph, a malformed
output or a digest mismatch resolves to ``CONFIDENTIAL`` rather than allowing
egress.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Protocol

import numpy as np
from anyio import to_thread

from settings import get_settings

logger = logging.getLogger(__name__)

#: Labels the safety graph emits, in ``config.json`` ``id2label`` order.
#: The head is multi-label (``problem_type: multi_label_classification``), so
#: each score is an independent sigmoid, not a softmax over the 16 classes.
SAFETY_LABELS: Final[tuple[str, ...]] = (
    "unsafe",
    "hate",
    "harassment",
    "violence",
    "weapons",
    "sexual",
    "sexual_minors",
    "self_harm",
    "criminal_planning",
    "drugs",
    "privacy",
    "profanity",
    "fraud_manipulation",
    "misinformation",
    "unauthorized_advice",
    "other",
)

#: ``id2label`` for the injection graph is ``{0: SAFE, 1: INJECTION}``.
_INJECTION_INDEX: Final[int] = 1

#: Categories with a confidentiality consequence, in decision-table priority
#: order. The remaining categories are logged for triage, not routed on.
CATEGORY_REASONS: Final[Mapping[str, str]] = {
    "privacy": "privacy_risk",
    "fraud_manipulation": "fraud_manipulation",
    "criminal_planning": "criminal_planning",
    "unauthorized_advice": "unauthorized_advice",
}

#: Cap the tokens considered per prompt/document. The graphs accept up to 8192
#: positions; anything longer is windowed rather than silently truncated.
_MAX_DOCUMENT_TOKENS: Final[int] = 8192

#: One token of padding when the tokenizer yields nothing (empty prompt).
_EMPTY_ID: Final[int] = 0


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
class EnsembleThresholds:
    """The three ADR-011 operating points, all tunable without a code change."""

    injection: float
    unsafe: float
    category: float


class _InjectionPredictor(Protocol):
    """Returns the probability that the text attempts prompt injection."""

    def predict(self, text: str) -> float: ...


class _SafetyPredictor(Protocol):
    """Returns one score per :data:`SAFETY_LABELS` entry."""

    def predict(self, text: str) -> Mapping[str, float]: ...


def decide_ensemble(
    injection_probability: float,
    safety_scores: Mapping[str, float],
    thresholds: EnsembleThresholds,
) -> Classification:
    """Apply the ADR-011 decision table to raw model scores.

    This is a pure function so the routing policy can be tested without an
    ONNX session: injection is evaluated first and cannot be overridden, then
    the aggregate ``unsafe`` gate, then the four confidentiality categories.
    """
    if injection_probability >= thresholds.injection:
        return Classification(
            label=Sensitivity.CONFIDENTIAL,
            confidence=round(injection_probability, 4),
            model="injection-guard",
            reason="prompt_injection_detected",
        )

    unsafe = safety_scores.get("unsafe", 0.0)
    matched = tuple(
        name for name in CATEGORY_REASONS if safety_scores.get(name, 0.0) >= thresholds.category
    )
    if unsafe >= thresholds.unsafe:
        return Classification(
            label=Sensitivity.CONFIDENTIAL,
            confidence=round(unsafe, 4),
            model="safety-guard",
            matched=("unsafe",),
            reason="unsafe_content",
        )
    for name, reason in CATEGORY_REASONS.items():
        if name in matched:
            return Classification(
                label=Sensitivity.CONFIDENTIAL,
                confidence=round(safety_scores.get(name, 0.0), 4),
                model="safety-guard",
                matched=matched,
                reason=reason,
            )

    highest = max([unsafe, *(safety_scores.get(name, 0.0) for name in CATEGORY_REASONS)])
    return Classification(
        label=Sensitivity.PUBLIC,
        confidence=round(1.0 - highest, 4),
        model="safety-guard",
        reason="public_content",
    )


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
            r"\b(?:passport|social security|bank account|medical record|diagnos\w*)\b",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        # IBANs formatted as ``CH93 0076 2011 6238 5295 7`` or unspaced.
        # Presidio redacts them, but a single trailing period can drop the
        # privacy model below threshold, so the format is also a deterministic
        # floor. The lookahead requires at least 11 characters after the check
        # digits (the shortest real BBAN, Norway), which keeps short coupon or
        # product codes from matching.
        "financial_identifier",
        4.0,
        re.compile(
            r"\b[A-Z]{2}\d{2}(?=(?:[ ]?[A-Z0-9]){11,30}\b)"
            r"(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b",
            re.IGNORECASE,
        ),
    ),
)

_RULE_MODEL: Final[str] = "semantic-rules"


class _OnnxGraph:
    """One ONNX graph plus its tokenizer, opened once per process.

    ``logits_windows`` returns per-window logits: long documents are sliced
    into overlapping windows (the model card's recommendation for indirect
    injection in tool output) and the caller reduces across them.
    """

    def __init__(
        self,
        *,
        graph: str,
        model_path: Path,
        tokenizer_path: Path,
        max_tokens: int,
        expected_sha256: str | None,
    ) -> None:
        if not model_path.is_file():
            raise ClassifierConfigurationError(f"{graph} model not found: {model_path}")
        if not tokenizer_path.is_file():
            raise ClassifierConfigurationError(f"{graph} tokenizer not found: {tokenizer_path}")
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        self._verify_digest(graph, model_path, expected_sha256)

        try:
            import onnxruntime
            from tokenizers import Tokenizer
        except ImportError as exc:  # pragma: no cover - dependencies are pinned
            raise ClassifierConfigurationError(
                "onnxruntime and tokenizers are required for the ONNX classifier"
            ) from exc

        try:
            tokenizer = Tokenizer.from_file(str(tokenizer_path))
            tokenizer.no_truncation()
            session = onnxruntime.InferenceSession(
                str(model_path),
                providers=_execution_providers(onnxruntime),
            )
        except Exception as exc:
            raise ClassifierConfigurationError(
                f"could not load {graph} artefacts from {model_path}"
            ) from exc

        input_names = {item.name for item in session.get_inputs()}
        if "input_ids" not in input_names:
            raise ClassifierConfigurationError(f"{graph} model has no input_ids input")

        self._graph = graph
        self._tokenizer = tokenizer
        self._session = session
        self._input_names = input_names
        self._max_tokens = max_tokens
        logger.info(
            "ONNX classifier graph ready",
            extra={
                "graph": graph,
                "model": str(model_path),
                "max_tokens": max_tokens,
                "providers": session.get_providers(),
            },
        )

    def logits_windows(self, text: str) -> list[np.ndarray]:
        """Return one flattened logit array per sliding window."""
        encoding = self._tokenizer.encode(text or "")
        ids = list(encoding.ids)[:_MAX_DOCUMENT_TOKENS]
        if not ids:
            ids = [_EMPTY_ID]
        return [self._run(window) for window in _windows(ids, self._max_tokens)]

    def _run(self, ids: list[int]) -> np.ndarray:
        feeds: dict[str, Any] = {"input_ids": np.array([ids], dtype=np.int64)}
        if "attention_mask" in self._input_names:
            feeds["attention_mask"] = np.ones((1, len(ids)), dtype=np.int64)
        if "token_type_ids" in self._input_names:
            feeds["token_type_ids"] = np.zeros((1, len(ids)), dtype=np.int64)
        outputs = self._session.run(None, feeds)
        return np.asarray(outputs[0], dtype=np.float64).reshape(-1)

    @staticmethod
    def _verify_digest(graph: str, model_path: Path, expected: str | None) -> None:
        if expected is None:
            return
        digest = hashlib.sha256()
        with model_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        actual = digest.hexdigest()
        if actual != expected:
            raise ClassifierConfigurationError(
                f"{graph} digest mismatch: expected {expected}, got {actual}"
            )


class _OnnxInjectionModel:
    """Prompt-injection guard: two logits, softmax, index 1 is INJECTION."""

    def __init__(self, graph: _OnnxGraph) -> None:
        self._graph = graph

    def predict(self, text: str) -> float:
        probabilities = [
            _softmax(window)[_INJECTION_INDEX] for window in self._graph.logits_windows(text)
        ]
        return float(max(probabilities))


class _OnnxSafetyModel:
    """Multi-label safety guard: one sigmoid per category, max over windows."""

    def __init__(self, graph: _OnnxGraph) -> None:
        self._graph = graph

    def predict(self, text: str) -> Mapping[str, float]:
        scores = [_sigmoid(window) for window in self._graph.logits_windows(text)]
        stacked = np.vstack(scores).max(axis=0)
        if stacked.size != len(SAFETY_LABELS):
            raise ClassifierConfigurationError(
                f"expected {len(SAFETY_LABELS)} safety labels, got {stacked.size}"
            )
        return {label: float(value) for label, value in zip(SAFETY_LABELS, stacked, strict=True)}


class SensitivityClassifier:
    """Confidentiality classifier: ensemble, single graph, or rule fallback."""

    def __init__(
        self,
        *,
        model_path: str | None = None,
        tokenizer_path: str | None = None,
        max_tokens: int | None = None,
        threshold: float | None = None,
        injection_model_path: str | None = None,
        injection_tokenizer_path: str | None = None,
        safety_model_path: str | None = None,
        safety_tokenizer_path: str | None = None,
        injection_max_tokens: int | None = None,
        safety_max_tokens: int | None = None,
        injection_threshold: float | None = None,
        safety_unsafe_threshold: float | None = None,
        safety_category_threshold: float | None = None,
        injection_model_sha256: str | None = None,
        safety_model_sha256: str | None = None,
        injection_predictor: _InjectionPredictor | None = None,
        safety_predictor: _SafetyPredictor | None = None,
        rules_floor: bool = True,
        require_models: bool = False,
    ) -> None:
        settings = get_settings()
        self._model_path = Path(model_path).expanduser() if model_path else None
        self._tokenizer_path = Path(tokenizer_path).expanduser() if tokenizer_path else None
        self._max_tokens = settings.classifier_max_tokens if max_tokens is None else max_tokens
        self._threshold = (
            settings.classifier_confidence_threshold if threshold is None else threshold
        )
        self._thresholds = EnsembleThresholds(
            injection=settings.injection_threshold
            if injection_threshold is None
            else injection_threshold,
            unsafe=settings.classifier_safety_unsafe_threshold
            if safety_unsafe_threshold is None
            else safety_unsafe_threshold,
            category=settings.classifier_safety_category_threshold
            if safety_category_threshold is None
            else safety_category_threshold,
        )
        _validate_operating_points(self._threshold, self._thresholds)
        if self._max_tokens <= 0:
            raise ValueError("max_tokens must be positive")

        self._injection = injection_predictor
        self._safety = safety_predictor
        self._rules_floor = rules_floor
        if self._injection is None and injection_model_path is not None:
            self._injection = _OnnxInjectionModel(
                self._build_graph(
                    graph="injection-guard",
                    model_path=injection_model_path,
                    tokenizer_path=injection_tokenizer_path,
                    max_tokens=settings.classifier_injection_max_tokens
                    if injection_max_tokens is None
                    else injection_max_tokens,
                    expected_sha256=injection_model_sha256,
                )
            )
        if self._safety is None and safety_model_path is not None:
            self._safety = _OnnxSafetyModel(
                self._build_graph(
                    graph="safety-guard",
                    model_path=safety_model_path,
                    tokenizer_path=safety_tokenizer_path,
                    max_tokens=settings.classifier_safety_max_tokens
                    if safety_max_tokens is None
                    else safety_max_tokens,
                    expected_sha256=safety_model_sha256,
                )
            )
        if (self._injection is None) != (self._safety is None):
            raise ClassifierConfigurationError(
                "the injection guard and the safety guard must be configured together"
            )

        self._session: Any | None = None
        self._tokenizer: Any | None = None
        if self._injection is None and self._model_path is not None:
            self._load_onnx()

        if require_models and not self.uses_model:
            raise ClassifierConfigurationError(
                "no classifier model configured outside ENVIRONMENT=local; set "
                "CLASSIFIER_INJECTION_MODEL_PATH and CLASSIFIER_SAFETY_MODEL_PATH "
                "(or CLASSIFIER_MODEL_PATH)"
            )

    # -- public API -------------------------------------------------------
    @property
    def uses_model(self) -> bool:
        """True when a model (ensemble or single graph) backs the decision."""
        return self._injection is not None or self._session is not None

    def classify(self, text: str) -> Classification:
        """Classify a prompt (synchronous; use :meth:`aclassify` in async code)."""
        if self._injection is not None and self._safety is not None:
            return self._classify_ensemble(text)
        if self._session is not None:
            return self._classify_onnx(text)
        return self._classify_rules(text)

    async def aclassify(self, text: str) -> Classification:
        return await to_thread.run_sync(self.classify, text)

    @property
    def model_name(self) -> str:
        if self._injection is not None:
            return "ensemble"
        return self._model_path.name if self._model_path is not None else _RULE_MODEL

    # -- ensemble ---------------------------------------------------------
    def ensemble_scores(self, text: str) -> tuple[float, Mapping[str, float]]:
        """Return the raw ensemble scores for evaluation and threshold tuning.

        Routing must use :meth:`classify` so the decision table and the
        deterministic rules floor still apply; this method deliberately skips
        both. It raises :class:`ClassifierConfigurationError` when the ensemble
        is not configured.
        """
        if self._injection is None or self._safety is None:
            raise ClassifierConfigurationError("ensemble is not configured")
        return self._injection.predict(text), self._safety.predict(text)

    def _classify_ensemble(self, text: str) -> Classification:
        if self._injection is None or self._safety is None:  # pragma: no cover - guarded above
            raise ClassifierConfigurationError("ensemble is not fully configured")
        try:
            injection_probability, safety_scores = self.ensemble_scores(text)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # Fail closed: a broken gate must never allow egress. The exception
            # type is logged, never the prompt text.
            logger.error(
                "classifier inference failed; failing closed",
                extra={"error": type(exc).__name__},
            )
            return Classification(
                label=Sensitivity.CONFIDENTIAL,
                confidence=1.0,
                model="ensemble",
                reason="classifier_error",
            )
        decision = decide_ensemble(injection_probability, safety_scores, self._thresholds)
        if decision.is_confidential or not self._rules_floor:
            return decision
        # Deterministic floor: the safety guard models harm, not corporate
        # secrecy, so "strictly confidential: board minutes" scores as harmless
        # content. Explicit markings and domain markers must never depend on a
        # learned notion of harm. The rules can only add CONFIDENTIAL.
        rule_decision = self._classify_rules(text)
        return rule_decision if rule_decision.is_confidential else decision

    @staticmethod
    def _build_graph(
        *,
        graph: str,
        model_path: str,
        tokenizer_path: str | None,
        max_tokens: int,
        expected_sha256: str | None,
    ) -> _OnnxGraph:
        path = Path(model_path).expanduser()
        return _OnnxGraph(
            graph=graph,
            model_path=path,
            tokenizer_path=_resolve_tokenizer(path, tokenizer_path),
            max_tokens=max_tokens,
            expected_sha256=expected_sha256,
        )

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

    # -- legacy single graph ---------------------------------------------
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
        return f"SensitivityClassifier(mode={self.model_name!r}, thresholds={self._thresholds!r})"


def _validate_operating_points(threshold: float, ensemble: EnsembleThresholds) -> None:
    for name, value in (
        ("threshold", threshold),
        ("injection_threshold", ensemble.injection),
        ("safety_unsafe_threshold", ensemble.unsafe),
        ("safety_category_threshold", ensemble.category),
    ):
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{name} must be within [0.0, 1.0]")


def _resolve_tokenizer(model_path: Path, explicit: str | None) -> Path:
    """Find the tokenizer beside the graph or at the repository root."""
    if explicit:
        return Path(explicit).expanduser()
    for candidate in (
        model_path.with_name("tokenizer.json"),
        model_path.parent.parent / "tokenizer.json",
    ):
        if candidate.is_file():
            return candidate
    raise ClassifierConfigurationError(
        f"tokenizer not found next to {model_path}; set the tokenizer path explicitly"
    )


def _windows(ids: list[int], window: int) -> list[list[int]]:
    """Overlapping token windows with a quarter-window stride."""
    if len(ids) <= window:
        return [ids]
    stride = max(1, window // 4)
    return [ids[start : start + window] for start in range(0, len(ids), stride)]


def _execution_providers(onnxruntime: Any) -> list[str]:
    """CUDA first, CPU fallback — the order ADR-011 specifies."""
    available = set(onnxruntime.get_available_providers())
    ordered = [
        name for name in ("CUDAExecutionProvider", "CPUExecutionProvider") if name in available
    ]
    return ordered or ["CPUExecutionProvider"]


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - np.max(logits)
    exponentials = np.exp(shifted)
    return np.asarray(exponentials / np.sum(exponentials), dtype=np.float64)


def _sigmoid(logits: np.ndarray) -> np.ndarray:
    # Numerically stable form: 1 / (1 + exp(-x)), split by sign.
    output = np.empty_like(logits, dtype=np.float64)
    positive = logits >= 0
    output[positive] = 1.0 / (1.0 + np.exp(-logits[positive]))
    negative_exp = np.exp(logits[~positive])
    output[~positive] = negative_exp / (1.0 + negative_exp)
    return output


@functools.lru_cache(maxsize=1)
def get_classifier() -> SensitivityClassifier:
    """Process-wide classifier from configuration."""
    settings = get_settings()
    return SensitivityClassifier(
        model_path=settings.classifier_model_path,
        tokenizer_path=settings.classifier_tokenizer_path,
        max_tokens=settings.classifier_max_tokens,
        threshold=settings.classifier_confidence_threshold,
        injection_model_path=settings.classifier_injection_model_path,
        injection_tokenizer_path=settings.classifier_injection_tokenizer_path,
        safety_model_path=settings.classifier_safety_model_path,
        safety_tokenizer_path=settings.classifier_safety_tokenizer_path,
        injection_max_tokens=settings.classifier_injection_max_tokens,
        safety_max_tokens=settings.classifier_safety_max_tokens,
        injection_threshold=settings.injection_threshold,
        safety_unsafe_threshold=settings.classifier_safety_unsafe_threshold,
        safety_category_threshold=settings.classifier_safety_category_threshold,
        injection_model_sha256=settings.classifier_injection_model_sha256,
        safety_model_sha256=settings.classifier_safety_model_sha256,
        rules_floor=settings.classifier_rules_floor,
        require_models=settings.environment != "local",
    )
