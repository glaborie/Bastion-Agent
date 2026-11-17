"""Startup warm-up of the guardrails (IDEA-067).

The first chat turn after a restart used to pay for Presidio's spaCy load and,
in a process that never classified, for the ONNX sessions too. Startup now
builds both through the accessors the request path uses, and a failure there is
a startup failure rather than a first-request 500.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from agent import runtime, warmup
from agent.routing import classifier as classifier_module
from gateway.main import lifespan
from gateway.routers import health


class _Recording:
    """Accessor double: records each build, optionally raises."""

    def __init__(self, name: str, calls: list[str], *, fail: bool = False) -> None:
        self._name = name
        self._calls = calls
        self._fail = fail

    def __call__(self) -> object:
        self._calls.append(self._name)
        if self._fail:
            raise RuntimeError(f"{self._name} graph missing")
        return object()


def _app_guards(calls: list[str], *, fail: str | None = None) -> tuple[Any, ...]:
    return (
        ("dlp", _Recording("dlp", calls, fail=fail == "dlp")),
        ("classifier", _Recording("classifier", calls, fail=fail == "classifier")),
    )


async def test_startup_builds_each_guard_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(warmup, "GUARDS", _app_guards(calls))

    async with lifespan(None):  # type: ignore[arg-type]
        assert calls == ["dlp", "classifier"]
        assert warmup.guards_are_warm() is True


@pytest.mark.parametrize("guard", ["dlp", "classifier"])
async def test_a_guard_that_cannot_be_built_stops_startup(
    monkeypatch: pytest.MonkeyPatch, guard: str
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(warmup, "GUARDS", _app_guards(calls, fail=guard))

    with pytest.raises(warmup.GuardWarmUpError, match=f"{guard} warm-up failed"):
        async with lifespan(None):  # type: ignore[arg-type]
            pytest.fail("a failed warm-up must not reach the serving state")
    assert warmup.guards_are_warm() is False


async def test_the_worker_warms_the_same_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(warmup, "GUARDS", _app_guards(calls))

    await runtime.startup({})
    try:
        assert calls == ["dlp", "classifier"]
    finally:
        await runtime.shutdown({})


async def _readiness(monkeypatch: pytest.MonkeyPatch, *, warm: bool) -> httpx.Response:
    async def reachable() -> bool:
        return True

    monkeypatch.setattr(health, "ping", reachable)
    monkeypatch.setattr(health, "guards_are_warm", lambda: warm)
    app = httpx.ASGITransport(app=_health_app())
    async with httpx.AsyncClient(transport=app, base_url="http://testserver") as client:
        return await client.get("/health/ready")


def _health_app() -> Any:
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(health.router)
    return app


async def test_readiness_withholds_ready_until_the_guards_are_warm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cold = await _readiness(monkeypatch, warm=False)
    assert cold.status_code == 503
    assert cold.json()["checks"] == {"database": True, "guards": False}

    warm = await _readiness(monkeypatch, warm=True)
    assert warm.status_code == 200
    assert warm.json()["status"] == "ready"


async def test_the_classifier_is_one_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    """Warm-up and the router must not build two ONNX session sets."""
    built: list[object] = []

    def fake_classifier(_config: object) -> object:
        instance = object()
        built.append(instance)
        return instance

    classifier_module.get_classifier.cache_clear()
    monkeypatch.setattr(classifier_module, "SensitivityClassifier", fake_classifier)
    try:
        assert classifier_module.get_classifier() is classifier_module.get_classifier()
        assert len(built) == 1
    finally:
        classifier_module.get_classifier.cache_clear()


@pytest.fixture(autouse=True)
def _cold_start() -> Iterator[None]:
    """Every test starts with the warm flag down and the caches empty."""
    warmup._warm = False  # pylint: disable=protected-access
    classifier_module.get_classifier.cache_clear()
    yield
    warmup._warm = False  # pylint: disable=protected-access
    classifier_module.get_classifier.cache_clear()
