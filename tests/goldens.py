"""Loader for the ADR-006 golden corpus.

The corpus is one JSON object per line. Fields:

``id``                  stable case identifier (also the pytest parameter id)
``category``            policy family: pii, corporate, injection, privacy,
                        fraud_manipulation, criminal_planning,
                        unauthorized_advice, public or borderline
``prompt``              the case text
``expected_label``      PUBLIC / CONFIDENTIAL, or null when the layer under test
                        owns the case (PII is DLP's job) or the row documents a
                        measured model gap
``expected_route``      local-llama / cloud-primary, or null
``expected_reason``     asserted reason code, or null when either the aggregate
                        gate or a category may legitimately fire first
``expected_redactions`` Presidio entity types that must be detected
``expected_score``      DeepEval threshold (always 1.0: zero tolerance)
``known_gap``           measured model miss, documented in ADR-011
``notes``               why the case exists
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final

GOLDENS_PATH: Final[Path] = Path(__file__).parent / "data" / "goldens.jsonl"


@dataclass(frozen=True, slots=True)
class Golden:
    ident: str
    category: str
    prompt: str
    expected_label: str | None
    expected_route: str | None
    expected_reason: str | None
    expected_redactions: tuple[str, ...]
    expected_score: float
    known_gap: bool
    notes: str


def load_goldens(path: Path = GOLDENS_PATH) -> list[Golden]:
    """Parse and return the corpus, failing loudly on a malformed row."""
    goldens: list[Golden] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        payload = json.loads(line)
        try:
            goldens.append(
                Golden(
                    ident=str(payload["id"]),
                    category=str(payload["category"]),
                    prompt=str(payload["prompt"]),
                    expected_label=payload.get("expected_label"),
                    expected_route=payload.get("expected_route"),
                    expected_reason=payload.get("expected_reason"),
                    expected_redactions=tuple(payload.get("expected_redactions", ())),
                    expected_score=float(payload.get("expected_score", 1.0)),
                    known_gap=bool(payload.get("known_gap", False)),
                    notes=str(payload.get("notes", "")),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"{path}:{line_number}: invalid golden entry: {exc}") from exc
    return goldens
