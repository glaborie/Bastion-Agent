"""Redis-backed record of one dashboard demo run (ADR-007).

The gateway creates a ``queued`` record and enqueues the job; the worker updates
the same key as the run moves to ``running`` and then to ``succeeded`` or
``failed``. The page polls the record, so the HTTP request that starts a
scenario never waits for classification, a model call or a database write.

The record is deliberately short-lived: a demo run is evidence for the person
watching it, not an audit trail. The ledger and the trace store keep the
canonical rows.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from redis.asyncio import Redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

RUN_KEY_PREFIX: Final[str] = "demo:run:"
#: One hour is long enough for a demo turn and short enough that a forgotten
#: browser tab cannot grow the keyspace forever.
RUN_TTL_SECONDS: Final[int] = 3600

STATUS_QUEUED: Final[str] = "queued"
STATUS_RUNNING: Final[str] = "running"
STATUS_SUCCEEDED: Final[str] = "succeeded"
STATUS_FAILED: Final[str] = "failed"

TERMINAL_STATUSES: Final[frozenset[str]] = frozenset({STATUS_SUCCEEDED, STATUS_FAILED})


class DemoRunUnavailableError(RuntimeError):
    """The run store could not be read or written."""


def new_run_id() -> str:
    """A fresh opaque run id (also the polling path parameter)."""
    return uuid.uuid4().hex


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True, slots=True)
class DemoRun:
    """One scenario invocation and, once finished, its evidence."""

    run_id: str
    scenario_id: str
    status: str
    actor_id: str
    session_id: str
    created_at: str
    finished_at: str | None = None
    summary: str | None = None
    facts: tuple[tuple[str, str], ...] = ()
    lines: tuple[str, ...] = ()
    links: tuple[tuple[str, str], ...] = ()
    error: str | None = None

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def to_json(self) -> str:
        return json.dumps(
            {
                "run_id": self.run_id,
                "scenario_id": self.scenario_id,
                "status": self.status,
                "actor_id": self.actor_id,
                "session_id": self.session_id,
                "created_at": self.created_at,
                "finished_at": self.finished_at,
                "summary": self.summary,
                "facts": [list(pair) for pair in self.facts],
                "lines": list(self.lines),
                "links": [list(pair) for pair in self.links],
                "error": self.error,
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> DemoRun:
        data: Any = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("demo run record is not an object")
        run_id = _required_text(data, "run_id")
        return cls(
            run_id=run_id,
            scenario_id=_required_text(data, "scenario_id"),
            status=_required_text(data, "status"),
            actor_id=_required_text(data, "actor_id"),
            session_id=_required_text(data, "session_id"),
            created_at=_required_text(data, "created_at"),
            finished_at=_optional_text(data.get("finished_at")),
            summary=_optional_text(data.get("summary")),
            facts=_parse_facts(data.get("facts")),
            lines=_parse_lines(data.get("lines")),
            links=_parse_facts(data.get("links")),
            error=_optional_text(data.get("error")),
        )


def _required_text(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"demo run record is missing {key!r}")
    return value


def _optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _parse_facts(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        return ()
    facts: list[tuple[str, str]] = []
    for item in value:
        if (
            isinstance(item, list)
            and len(item) == 2
            and all(isinstance(part, str) for part in item)
        ):
            facts.append((item[0], item[1]))
    return tuple(facts)


def _parse_lines(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _key(run_id: str) -> str:
    return f"{RUN_KEY_PREFIX}{run_id}"


async def save_run(redis: Redis, run: DemoRun) -> None:
    """Store the run with the short demo TTL, refreshing it on every update."""
    try:
        await redis.set(_key(run.run_id), run.to_json(), ex=RUN_TTL_SECONDS)
    except RedisError as exc:
        raise DemoRunUnavailableError("the demo run store is unreachable") from exc


async def load_run(redis: Redis, run_id: str) -> DemoRun | None:
    """Read a run, or ``None`` when it expired or was never created.

    A malformed record is treated as absent rather than rendered: the page can
    say "not found", but it must never show half-parsed evidence.
    """
    try:
        raw = await redis.get(_key(run_id))
    except RedisError as exc:
        raise DemoRunUnavailableError("the demo run store is unreachable") from exc
    if not isinstance(raw, str):
        return None
    try:
        return DemoRun.from_json(raw)
    except (ValueError, TypeError):
        logger.warning("Discarding a malformed demo run record", extra={"run_id": run_id})
        return None
