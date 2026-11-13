"""Contract tests for the per-item backlog store and its renderer."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from scripts import check_backlog
from scripts.check_backlog import (
    create_item,
    load,
    next_id,
    render,
    validate,
    write_atomic,
)

ITEM = """### IDEA-{number}: {title}

- status: {status}
- priority: P2
- phase: v0.3
- area: tooling
- tags: backlog
- depends-on: {deps}
- spec: ADR-008
- created: 2026-01-01
- updated: 2026-01-01
- source: test

**Problem**

The store is described here.

**Outcome**

The store behaves as described.

**Acceptance**

- [ ] `uv run pytest -q`
"""


def make_store(root: Path, *items: tuple[str, str, str]) -> Path:
    """Write a backlog store: (title, status, depends-on) per item, ids from 001."""
    (root / "backlog" / "items").mkdir(parents=True)
    (root / "backlog" / "config.toml").write_text(
        'current-phase = "v0.3"\nwip-limit = 3\n', encoding="utf-8"
    )
    for index, (title, status, deps) in enumerate(items, start=1):
        path = root / "backlog" / "items" / f"IDEA-{index:03d}-item.md"
        path.write_text(
            ITEM.format(number=f"{index:03d}", title=title, status=status, deps=deps),
            encoding="utf-8",
        )
    return root


def test_load_and_validate_accepts_a_clean_store(tmp_path: Path) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"), ("Second", "inbox", "-"))

    meta, items, load_errors = load(root)
    errors, _ = validate(meta, items, load_errors)

    assert not errors
    assert [item.id for item in items] == ["IDEA-001", "IDEA-002"]
    assert meta == {"current-phase": "v0.3", "wip-limit": "3"}


def test_duplicate_id_is_rejected(tmp_path: Path) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"))
    # A second branch allocated the same number: a different file, same heading.
    (root / "backlog" / "items" / "IDEA-001-copy.md").write_text(
        ITEM.format(number="001", title="Copy", status="inbox", deps="-"), encoding="utf-8"
    )

    meta, items, load_errors = load(root)
    errors, _ = validate(meta, items, load_errors)

    assert any("duplicate id" in error for error in errors)


def test_filename_must_carry_the_id(tmp_path: Path) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"))
    (root / "backlog" / "items" / "IDEA-001-item.md").rename(
        root / "backlog" / "items" / "first.md"
    )

    _, _, load_errors = load(root)

    assert any("filename must start with" in error for error in load_errors)


def test_unfinished_skeleton_is_rejected(tmp_path: Path) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"))
    path = root / "backlog" / "items" / "IDEA-001-item.md"
    path.write_text(
        path.read_text(encoding="utf-8").replace("The store is described here.", "TODO: fill"),
        encoding="utf-8",
    )

    meta, items, load_errors = load(root)
    errors, _ = validate(meta, items, load_errors)

    assert any("unfinished skeleton" in error for error in errors)


def test_render_is_stable(tmp_path: Path) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"), ("Second", "ready", "IDEA-001"))

    meta, items, _ = load(root)
    first = render(meta, items)
    second = render(meta, items)
    _, reloaded, _ = load(root)

    assert first == second == render(meta, reloaded)
    assert "### Ready (1)" in first
    assert "| IDEA-002 | ready |" in first
    assert "**Problem**" not in first


def test_next_id_counts_from_the_highest(tmp_path: Path) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"), ("Second", "inbox", "-"))

    _, items, _ = load(root)

    assert next_id(items) == "IDEA-003"


def test_create_item_refuses_to_overwrite(tmp_path: Path) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"))
    meta, items, _ = load(root)
    existing = root / "backlog" / "items" / "IDEA-002-second.md"
    existing.write_text("occupied\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        create_item(root, meta, items, "Second")

    assert existing.read_text(encoding="utf-8") == "occupied\n"


def test_write_atomic_keeps_the_previous_index_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = tmp_path / "BACKLOG.md"
    index.write_text("previous\n", encoding="utf-8")

    def boom(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(check_backlog.os, "replace", boom)

    with pytest.raises(OSError):
        write_atomic(index, "replacement\n")

    assert index.read_text(encoding="utf-8") == "previous\n"
    assert [path.name for path in tmp_path.iterdir()] == ["BACKLOG.md"]


def test_repository_store_renders_every_item() -> None:
    root = Path(__file__).resolve().parents[1]

    meta, items, load_errors = load(root)
    errors, _ = validate(meta, items, load_errors)
    rendered = render(meta, items)

    assert not errors
    assert items
    assert rendered == render(meta, load(root)[1])
    for item in items:
        assert f"`{item.id}`" in rendered


def test_list_shows_only_the_requested_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = make_store(
        tmp_path, ("First", "inbox", "-"), ("Second", "inbox", "-"), ("Third", "ready", "-")
    )

    assert check_backlog.main(["--root", str(root), "--list", "inbox"]) == 0

    printed = capsys.readouterr().out
    assert "IDEA-001" in printed
    assert "IDEA-002" in printed
    assert "IDEA-003" not in printed


def test_list_reports_an_empty_status(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"))

    assert check_backlog.main(["--root", str(root), "--list", "done"]) == 0

    assert "no done items" in capsys.readouterr().out


def test_list_json_carries_the_status(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"))

    assert check_backlog.main(["--root", str(root), "--list", "inbox", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "inbox"
    assert [item["id"] for item in payload["items"]] == ["IDEA-001"]


def test_list_rejects_an_unknown_status(tmp_path: Path) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"))

    with pytest.raises(SystemExit):
        check_backlog.main(["--root", str(root), "--list", "nonsense"])


def test_set_promotes_an_item_and_bumps_updated(tmp_path: Path) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"))
    path = root / "backlog" / "items" / "IDEA-001-item.md"

    assert check_backlog.main(["--root", str(root), "--set", "IDEA-001", "ready"]) == 0

    text = path.read_text(encoding="utf-8")
    assert "- status: ready" in text
    assert f"- updated: {date.today().isoformat()}" in text


def test_set_refuses_a_transition_that_would_be_invalid(tmp_path: Path) -> None:
    # 'done' with an unticked acceptance box, and 'blocked' with no reason, are
    # both rejected by the validator; the file must be left untouched.
    root = make_store(tmp_path, ("First", "inbox", "-"))
    path = root / "backlog" / "items" / "IDEA-001-item.md"
    before = path.read_text(encoding="utf-8")

    assert check_backlog.main(["--root", str(root), "--set", "IDEA-001", "done"]) == 1
    assert check_backlog.main(["--root", str(root), "--set", "IDEA-001", "blocked"]) == 1

    assert path.read_text(encoding="utf-8") == before


def test_set_rejects_an_unknown_item_or_status(tmp_path: Path) -> None:
    root = make_store(tmp_path, ("First", "inbox", "-"))

    assert check_backlog.main(["--root", str(root), "--set", "IDEA-999", "ready"]) == 1
    assert check_backlog.main(["--root", str(root), "--set", "IDEA-001", "nonsense"]) == 1
