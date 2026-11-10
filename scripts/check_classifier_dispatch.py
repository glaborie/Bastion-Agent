#!/usr/bin/env python3
"""Record the host and decide whether the int8 graphs reproduce calibration.

    uv run python scripts/check_classifier_dispatch.py
    uv run python scripts/check_classifier_dispatch.py --json

Prints ``reference`` or ``dispatch_anomaly`` for the pinned classifier graphs,
appends the same facts to ``$GITHUB_STEP_SUMMARY`` and, in Actions, writes
``verdict=<name>`` to ``$GITHUB_OUTPUT`` so the eval job can exempt the golden
gate (ADR-011). The exit status is always 0 — the verdict is data for the gate,
not a gate itself. ``unknown`` means the graphs are absent; the gate then skips
and stays red, exactly as before.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
from pathlib import Path
from typing import Any, Final

from agent.routing.classifier import SensitivityClassifier
from agent.routing.dispatch import (
    CALIBRATED_ON,
    CALIBRATION_HOST,
    DispatchVerdict,
    evaluate,
)
from settings import Settings

INJECTION_GRAPH: Final[Path] = Path("models/prompt-injection-guard-small/onnx/model_quantized.onnx")
SAFETY_GRAPH: Final[Path] = Path("models/content-safety-guard-small/onnx/model_quantized.onnx")
NO_AVX512: Final[str] = "(none)"


def host_facts(cpuinfo: Path = Path("/proc/cpuinfo")) -> tuple[str, str]:
    """Return the CPU model name and its AVX-512 flags (``(none)`` when absent)."""
    try:
        text = cpuinfo.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return platform.processor() or "unknown", NO_AVX512
    model = next(
        (
            line.split(":", 1)[1].strip()
            for line in text.splitlines()
            if line.startswith("model name")
        ),
        platform.processor() or "unknown",
    )
    flags = sorted(set(re.findall(r"avx512[a-z_]*", text)))
    return model, " ".join(flags) or NO_AVX512


def build_classifier(injection: Path, safety: Path) -> SensitivityClassifier:
    """Construct the ensemble the way the eval gate does (coded defaults)."""
    settings = Settings(_env_file=None)
    return SensitivityClassifier(
        injection_model_path=str(injection),
        safety_model_path=str(safety),
        injection_threshold=settings.injection_threshold,
        safety_unsafe_threshold=settings.classifier_safety_unsafe_threshold,
        safety_category_threshold=settings.classifier_safety_category_threshold,
        rules_floor=settings.classifier_rules_floor,
    )


def build_report(verdict: DispatchVerdict | None, host: str, flags: str) -> dict[str, Any]:
    """Shape the verdict as the JSON artifact and the job summary both read."""
    return {
        "verdict": verdict.name if verdict is not None else "unknown",
        "host": host,
        "avx512": flags,
        "calibration_host": CALIBRATION_HOST,
        "calibrated_on": CALIBRATED_ON,
        "sentinels": [
            {
                "id": row.sentinel.ident,
                "expected": row.sentinel.expected_label,
                "got": row.label,
                "reason": row.reason,
                "confidence": round(row.confidence, 4),
                "calibration_injection": row.sentinel.injection,
                "calibration_unsafe": row.sentinel.unsafe,
            }
            for row in (verdict.results if verdict is not None else ())
        ],
    }


def _markdown(report: dict[str, Any]) -> str:
    verdict = report["verdict"]
    lines = [
        f"### Classifier inference environment: `{verdict}`",
        "",
        f"- host: `{report['host']}`",
        f"- AVX-512 flags: `{report['avx512']}`",
        f"- calibration: `{report['calibration_host']}` ({report['calibrated_on']})",
        "",
        "| sentinel | calibration | this host |",
        "|---|---|---|",
    ]
    for row in report["sentinels"]:
        lines.append(
            f"| {row['id']} | {row['expected']} | {row['got']}/{row['reason']} "
            f"{row['confidence']:.4f} |"
        )
    lines.append("")
    if verdict == "dispatch_anomaly":
        lines.append(
            "Every benign sentinel is blocked while the injection sentinel is still "
            "detected: this is the AVX2-only int8 path, so the golden ratio "
            "assertions are exempt (ADR-011). The exemption is recorded in "
            "`artifacts/evals/latest.json` under `exempt_gates`."
        )
    elif verdict == "reference":
        lines.append(
            "The host reproduces the calibration verdicts; the golden gate runs "
            "its full zero-tolerance assertions."
        )
    else:
        lines.append(
            "The graphs are not present, so no verdict was taken; the classifier "
            "gate will skip and the run stays red."
        )
    return "\n".join(lines) + "\n"


def _emit(report: dict[str, Any]) -> None:
    """Write the GitHub step summary and output when Actions provides them."""
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write(_markdown(report))
    output_path = os.getenv("GITHUB_OUTPUT")
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as handle:
            handle.write(f"verdict={report['verdict']}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--injection-model", type=Path, default=INJECTION_GRAPH)
    parser.add_argument("--safety-model", type=Path, default=SAFETY_GRAPH)
    parser.add_argument("--json", action="store_true", help="print the verdict as JSON")
    args = parser.parse_args(argv)

    host, flags = host_facts()
    if not (args.injection_model.is_file() and args.safety_model.is_file()):
        verdict = None
    else:
        verdict = evaluate(build_classifier(args.injection_model, args.safety_model))

    report = build_report(verdict, host, flags)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_markdown(report), end="")
    _emit(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
