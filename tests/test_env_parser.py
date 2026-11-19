"""The one Compose-style ``.env`` reader both scripts now share (IDEA-081)."""

from __future__ import annotations

from pathlib import Path

from scripts._env import read_env
from scripts.check_env_vault import read_env as env_vault_read
from scripts.image_inventory import read_env as image_inventory_read

FIXTURE = """\
# a comment
PLAIN=value
SPACED = spaced value
export EXPORTED=exported
export  WIDE=wide
SINGLE='single'
DOUBLE="double"
BAD-KEY=ignored
9NUM=ignored
EMPTY=
DUP=first
DUP=second
INLINE=value # note
just-a-line
"""

EXPECTED = {
    "PLAIN": "value",
    "SPACED": "spaced value",
    "EXPORTED": "exported",
    "WIDE": "wide",
    "SINGLE": "single",
    "DOUBLE": "double",
    "EMPTY": "",
    "DUP": "second",
    "INLINE": "value # note",
}


def test_grammar(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(FIXTURE, encoding="utf-8")
    assert read_env(path) == EXPECTED


def test_absent_file_reads_as_empty(tmp_path: Path) -> None:
    assert not read_env(tmp_path / "missing.env")


def test_both_scripts_return_the_same_mapping(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(FIXTURE, encoding="utf-8")
    assert env_vault_read(path) == image_inventory_read(path) == EXPECTED
