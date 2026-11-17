"""Labelled-set gate for the frustration detector (ADR-022, IDEA-070).

The corpus is operator-labelled transcripts: 24 conversations a human would call
frustrated (including the two live misses) and 29 neutral support conversations,
several of them deliberately baiting the vocabulary ("broken link", "frustrated
customer", "when should I escalate a ticket to a human?"). Zero tolerance, like
the other golden gates: one missed complaint or one flagged neutral fails.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent.sentiment import assess

CORPUS = Path(__file__).parent / "data" / "frustration.jsonl"
#: Measured on 2026-11-17 with the rule that ships; quoted in ADR-022 decision 2.
FLOOR_POSITIVES = 24
FLOOR_NEGATIVES = 29


def _rows() -> list[dict[str, object]]:
    lines = CORPUS.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _turns(row: dict[str, object]) -> list[tuple[str, str]]:
    return [("user", str(turn)) for turn in row["turns"]]  # type: ignore[union-attr]


def test_the_labelled_set_keeps_its_size_and_shape() -> None:
    rows = _rows()
    positives = [row for row in rows if row["label"] == "positive"]
    negatives = [row for row in rows if row["label"] == "negative"]

    assert len(positives) == FLOOR_POSITIVES
    assert len(negatives) == FLOOR_NEGATIVES
    assert len({row["id"] for row in rows}) == len(rows)
    assert all(_turns(row) for row in rows)


def test_every_labelled_complaint_fires_and_no_neutral_conversation_does() -> None:
    failures = []
    for row in _rows():
        expected = row["label"] == "positive"
        verdict = assess(_turns(row))
        if (verdict is not None) != expected:
            failures.append(f"{row['id']}: expected {row['label']}, got {verdict}")

    assert not failures, "frustration gate failed:\n" + "\n".join(failures)


def test_the_two_live_misses_are_in_the_corpus() -> None:
    ids = {row["id"] for row in _rows()}

    assert {"pos-live-button-f419", "pos-live-button-2619"} <= ids
