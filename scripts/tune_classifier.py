#!/usr/bin/env python3
"""Sweep the ADR-011 classifier thresholds against the golden corpus.

    uv run python scripts/tune_classifier.py
    uv run python scripts/tune_classifier.py --json

The tuner reads ``tests/data/goldens.jsonl``, runs the real ensemble without
the deterministic rules floor (so it measures the *models*), and reports for
each signal the highest benign score, the lowest positive score and every
false-positive-free threshold interval.

The gate itself (``tests/test_classifier_evals.py``) is separate: it asserts
the routing labels, so this script only produces the evidence recorded in
ADR-011. Re-run it whenever the corpus, the models or a threshold changes.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

from agent.routing.classifier import (
    CATEGORY_REASONS,
    ClassifierConfigurationError,
    EnsembleThresholds,
    SensitivityClassifier,
    decide_ensemble,
)
from settings import get_settings

GOLDENS: Final[Path] = Path("tests/data/goldens.jsonl")

#: Categories the models are expected to resolve; the deterministic rules
#: floor owns ``corporate``/``pii`` rows and is measured separately.
SAFETY_CATEGORIES: Final[frozenset[str]] = frozenset(CATEGORY_REASONS)
BENIGN_CATEGORIES: Final[frozenset[str]] = frozenset({"public", "borderline"})

INJECTION_GRID: Final[tuple[float, ...]] = tuple(round(0.30 + 0.02 * i, 2) for i in range(31))
UNSAFE_GRID: Final[tuple[float, ...]] = tuple(round(0.10 + 0.02 * i, 2) for i in range(41))
CATEGORY_GRID: Final[tuple[float, ...]] = tuple(round(0.05 + 0.05 * i, 2) for i in range(12))


@dataclass(frozen=True, slots=True)
class Golden:
    ident: str
    category: str
    prompt: str
    expected_label: str | None
    known_gap: bool


@dataclass(frozen=True, slots=True)
class Scored:
    golden: Golden
    injection: float
    unsafe: float
    categories: dict[str, float]

    @property
    def safety_max(self) -> float:
        return max([self.unsafe, *self.categories.values()])


def load_goldens(path: Path) -> list[Golden]:
    if not path.is_file():
        raise SystemExit(f"golden corpus not found: {path}")
    goldens: list[Golden] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        payload = json.loads(line)
        try:
            goldens.append(
                Golden(
                    ident=payload["id"],
                    category=payload["category"],
                    prompt=payload["prompt"],
                    expected_label=payload["expected_label"],
                    known_gap=bool(payload.get("known_gap", False)),
                )
            )
        except (KeyError, TypeError) as exc:
            raise SystemExit(f"{path}:{line_number}: invalid golden entry: {exc}") from exc
    return goldens


def score_all(classifier: SensitivityClassifier, goldens: list[Golden]) -> list[Scored]:
    scored: list[Scored] = []
    for golden in goldens:
        injection, safety = classifier.ensemble_scores(golden.prompt)
        scored.append(
            Scored(
                golden=golden,
                injection=injection,
                unsafe=safety.get("unsafe", 0.0),
                categories={name: float(safety.get(name, 0.0)) for name in CATEGORY_REASONS},
            )
        )
    return scored


@dataclass(frozen=True, slots=True)
class SweepPoint:
    threshold: float
    recall: float
    fp: float


@dataclass(frozen=True, slots=True)
class SignalReport:
    signal: str
    highest_benign: float
    lowest_positive: float
    fp_free_interval: tuple[float, float] | None
    current: float
    current_fp: float
    current_recall: float
    sweep: tuple[SweepPoint, ...]


@dataclass(frozen=True, slots=True)
class JointReport:
    injection: float
    unsafe: float
    category: float
    recall: float
    fp_rate: float
    blocked: int
    positives: int


@dataclass(frozen=True, slots=True)
class Report:
    rows: int
    injection_positives: int
    safety_positives: int
    benign: int
    current: EnsembleThresholds
    signals: tuple[SignalReport, ...]
    joint: tuple[JointReport, ...]
    misses: tuple[dict[str, object], ...]


def _signal(value: Scored, name: str) -> float:
    if name == "injection":
        return value.injection
    if name == "unsafe":
        return value.unsafe
    if name == "category":
        return max(value.categories.values())
    return value.categories[name]


def _rate(values: list[Scored], name: str, threshold: float) -> float:
    if not values:
        return 0.0
    return sum(1 for value in values if _signal(value, name) >= threshold) / len(values)


def _fp_free_interval(
    benign: list[Scored], name: str, grid: tuple[float, ...]
) -> tuple[float, float] | None:
    """Return the lowest and highest grid threshold with zero false positives."""
    safe = [threshold for threshold in grid if _rate(benign, name, threshold) == 0.0]
    return (min(safe), max(safe)) if safe else None


def _report_signal(
    name: str,
    positives: list[Scored],
    benign: list[Scored],
    grid: tuple[float, ...],
    current: float,
) -> SignalReport:
    highest_benign = max((_signal(value, name) for value in benign), default=0.0)
    lowest_positive = min((_signal(value, name) for value in positives), default=0.0)
    interval = _fp_free_interval(benign, name, grid)
    return SignalReport(
        signal=name,
        highest_benign=round(highest_benign, 4),
        lowest_positive=round(lowest_positive, 4),
        fp_free_interval=(
            (round(interval[0], 3), round(interval[1], 3)) if interval is not None else None
        ),
        current=current,
        current_fp=round(_rate(benign, name, current), 4),
        current_recall=round(_rate(positives, name, current), 4),
        sweep=tuple(
            SweepPoint(
                threshold=threshold,
                recall=round(_rate(positives, name, threshold), 4),
                fp=round(_rate(benign, name, threshold), 4),
            )
            for threshold in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.662, 0.7, 0.8, 0.9)
            if threshold <= max(grid) + 1e-9
        ),
    )


def _misses(
    scored: list[Scored],
    thresholds: EnsembleThresholds,
    rules: SensitivityClassifier,
) -> tuple[dict[str, object], ...]:
    """Rows the whole gate leaves public, with the score that would have caught them.

    A row the deterministic rules floor already blocks is not a model miss.
    """
    missed: list[dict[str, object]] = []
    for value in scored:
        golden = value.golden
        if golden.category not in SAFETY_CATEGORIES and golden.category != "injection":
            continue
        if rules.classify(golden.prompt).is_confidential:
            continue
        decision = decide_ensemble(
            value.injection, value.categories | {"unsafe": value.unsafe}, thresholds
        )
        if not decision.is_confidential:
            missed.append(
                {
                    "id": golden.ident,
                    "category": golden.category,
                    "known_gap": golden.known_gap,
                    "injection": round(value.injection, 4),
                    "unsafe": round(value.unsafe, 4),
                    "categories": {k: round(v, 4) for k, v in value.categories.items()},
                }
            )
    return tuple(missed)


def _joint(
    scored: list[Scored],
    thresholds: EnsembleThresholds,
    rules: SensitivityClassifier,
) -> JointReport:
    """Overall gate recall/FP for one threshold set, rules floor included."""
    positives = [
        value
        for value in scored
        if value.golden.category in SAFETY_CATEGORIES or value.golden.category == "injection"
    ]
    benign = [value for value in scored if value.golden.category in BENIGN_CATEGORIES]
    blocked = sum(
        1
        for value in positives
        if rules.classify(value.golden.prompt).is_confidential
        or decide_ensemble(
            value.injection, value.categories | {"unsafe": value.unsafe}, thresholds
        ).is_confidential
    )
    false_positives = sum(
        1
        for value in benign
        if decide_ensemble(
            value.injection, value.categories | {"unsafe": value.unsafe}, thresholds
        ).is_confidential
    )
    return JointReport(
        injection=thresholds.injection,
        unsafe=thresholds.unsafe,
        category=thresholds.category,
        recall=round(blocked / len(positives), 4) if positives else 0.0,
        fp_rate=round(false_positives / len(benign), 4) if benign else 0.0,
        blocked=blocked,
        positives=len(positives),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    args = parser.parse_args(argv)

    settings = get_settings()
    try:
        classifier = SensitivityClassifier(
            injection_model_path=settings.classifier_injection_model_path,
            injection_tokenizer_path=settings.classifier_injection_tokenizer_path,
            safety_model_path=settings.classifier_safety_model_path,
            safety_tokenizer_path=settings.classifier_safety_tokenizer_path,
            rules_floor=False,
        )
    except ClassifierConfigurationError as exc:
        print(f"classifier unavailable: {exc}", file=sys.stderr)
        return 2
    if not classifier.uses_model:
        print("no ensemble configured; set CLASSIFIER_INJECTION_MODEL_PATH", file=sys.stderr)
        return 2

    goldens = load_goldens(GOLDENS)
    scored = score_all(classifier, goldens)
    rules = SensitivityClassifier(
        model_path=None,
        threshold=settings.classifier_confidence_threshold,
    )

    injection_positives = [value for value in scored if value.golden.category == "injection"]
    safety_positives = [value for value in scored if value.golden.category in SAFETY_CATEGORIES]
    benign = [value for value in scored if value.golden.category in BENIGN_CATEGORIES]

    current = EnsembleThresholds(
        injection=settings.injection_threshold,
        unsafe=settings.classifier_safety_unsafe_threshold,
        category=settings.classifier_safety_category_threshold,
    )
    category_signal = "category"
    report = Report(
        rows=len(goldens),
        injection_positives=len(injection_positives),
        safety_positives=len(safety_positives),
        benign=len(benign),
        current=current,
        signals=(
            _report_signal(
                "injection", injection_positives, benign, INJECTION_GRID, current.injection
            ),
            _report_signal("unsafe", safety_positives, benign, UNSAFE_GRID, current.unsafe),
            _report_signal(
                category_signal, safety_positives, benign, CATEGORY_GRID, current.category
            ),
        ),
        misses=_misses(scored, current, rules),
        joint=(
            _joint(scored, current, rules),
            _joint(scored, EnsembleThresholds(current.injection, current.unsafe, 0.2), rules),
        ),
    )

    if args.json:
        print(json.dumps(asdict(report), indent=2))
        return 0

    print(
        f"corpus: {report.rows} rows | injection positives: {report.injection_positives} | "
        f"safety positives: {report.safety_positives} | benign: {report.benign}\n"
    )
    print(
        f"current: injection >= {current.injection:.3f}, unsafe >= {current.unsafe:.2f}, "
        f"category >= {current.category:.2f}\n"
    )
    print(
        f"{'signal':<20}{'benign max':>11}{'positive min':>14}{'fp-free range':>20}"
        f"{'current':>9}{'FP':>7}{'recall':>8}"
    )
    for signal in report.signals:
        interval = signal.fp_free_interval
        interval_text = f"{interval[0]:.3f}-{interval[1]:.3f}" if interval else "none"
        print(
            f"{signal.signal:<20}{signal.highest_benign:>11.3f}"
            f"{signal.lowest_positive:>14.3f}{interval_text:>20}"
            f"{signal.current:>9.3f}{signal.current_fp:>7.3f}"
            f"{signal.current_recall:>8.3f}"
        )

    print("\nthreshold sweep (recall / false-positive rate)")
    for signal in report.signals:
        print(f"  {signal.signal}:")
        for point in signal.sweep:
            marker = " <- current" if abs(point.threshold - signal.current) < 1e-9 else ""
            print(
                f"    {point.threshold:>5.3f}  recall {point.recall:.3f}  fp {point.fp:.3f}{marker}"
            )

    print("\njoint gate (rules floor included):")
    for joint in report.joint:
        print(
            f"  injection {joint.injection:.3f}, unsafe {joint.unsafe:.2f}, "
            f"category {joint.category:.2f}: recall {joint.recall:.3f} "
            f"({joint.blocked}/{joint.positives}), benign FP {joint.fp_rate:.3f}"
        )

    print("\nmisses at the current operating point:")
    if not report.misses:
        print("  none")
    for miss in report.misses:
        flag = " (known gap)" if miss["known_gap"] else ""
        print(
            f"  {miss['id']}{flag}: injection {miss['injection']:.3f}, "
            f"unsafe {miss['unsafe']:.3f}, categories {miss['categories']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
