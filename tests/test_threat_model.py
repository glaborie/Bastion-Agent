"""The threat-model control table is checked against the tree, not trusted."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_threat_model import check_table

ROOT = Path(__file__).resolve().parents[1]

HEADER = """# Threat model

## 4. Control status summary

| Control | Status | Where |
|---|---|---|
"""


def document(*rows: str) -> str:
    return HEADER + "\n".join(rows) + "\n\n## 5. Threats\n"


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    (tmp_path / "impl.py").write_text("", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_impl.py").write_text("", encoding="utf-8")
    return tmp_path


def test_a_consistent_row_passes(tree: Path) -> None:
    errors = check_table(document("| Thing | LIVE | `impl.py`, `tests/test_impl.py` |"), tree)
    assert not errors, errors


def test_a_duplicate_control_name_fails(tree: Path) -> None:
    errors = check_table(
        document(
            "| Thing | LIVE | `impl.py`, `tests/test_impl.py` |",
            "| thing! | LIVE | `impl.py`, `tests/test_impl.py` |",
        ),
        tree,
    )
    assert any("duplicate control" in error for error in errors)


def test_a_live_row_naming_a_missing_path_fails(tree: Path) -> None:
    errors = check_table(document("| Thing | LIVE | `gone.py`, `tests/test_impl.py` |"), tree)
    assert any("missing path 'gone.py'" in error for error in errors)


def test_a_live_row_naming_no_test_file_fails(tree: Path) -> None:
    errors = check_table(document("| Thing | LIVE | `impl.py` |"), tree)
    assert any("names no tests/ file" in error for error in errors)


def test_a_planned_row_naming_an_existing_path_fails(tree: Path) -> None:
    errors = check_table(document("| Thing | PLANNED | `impl.py` |"), tree)
    assert any("PLANNED" in error and "'impl.py'" in error for error in errors)


def test_the_repository_table_passes() -> None:
    text = (ROOT / "THREAT_MODEL.md").read_text(encoding="utf-8")
    errors = check_table(text, ROOT)
    assert not errors, errors
