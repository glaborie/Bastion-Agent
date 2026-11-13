"""Split collected tests between isolated CI runners without changing their order."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--ci-shard", help="Run shard INDEX/TOTAL, numbered from 1")


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    value = config.getoption("--ci-shard")
    if value is None:
        return
    try:
        index, total = (int(part) for part in value.split("/"))
        if total < 2 or not 1 <= index <= total:
            raise ValueError
    except ValueError as exc:
        raise pytest.UsageError("--ci-shard must be INDEX/TOTAL with 1 <= INDEX <= TOTAL") from exc

    nodeids = sorted(item.nodeid for item in items)
    if len(nodeids) != len(set(nodeids)):
        raise pytest.UsageError("--ci-shard requires unique collected test IDs")
    selected_ids = set(nodeids[index - 1 :: total])
    selected = [item for item in items if item.nodeid in selected_ids]
    deselected = [item for item in items if item.nodeid not in selected_ids]
    config.hook.pytest_deselected(items=deselected)
    items[:] = selected
