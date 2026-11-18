#!/usr/bin/env python3
"""Apply ``config/uptime-kuma/monitors.json`` to a running Uptime Kuma.

Uptime Kuma has no endpoint for creating a monitor (its ``/api`` is read-only
and alpha), so this speaks the dashboard's own Socket.IO protocol over
Engine.IO long-polling: create the first admin account on a fresh instance,
log in, read the monitor list, then ``add`` one monitor per entry that is not
there yet. Running it twice converges instead of duplicating, which is the
point: the monitor set is a committed file, not a sequence of clicks in a UI
that nobody repeats after a ``down -v``.

The credential comes from ``UPTIME_KUMA_ADMIN_USER``/``UPTIME_KUMA_ADMIN_PASSWORD``
in ``.env`` (the process environment wins); there is no default password, and
the account is created with whatever the operator set, so a fresh instance never
has a factory login.

    docker compose --profile infra up -d uptime-kuma
    uv run python scripts/seed_uptime_kuma.py

Existing monitors are left alone: renaming or retuning one is a dashboard edit,
not a seed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

import httpx

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "config" / "uptime-kuma" / "monitors.json"
DEFAULT_URL = "http://127.0.0.1:3001"
ENV_FILE = ROOT / ".env"
PACKET_SEPARATOR = "\x1e"

# Fields every monitor needs: `add` reads them directly, so omitting one is a
# TypeError in the server rather than a validation message.
MONITOR_DEFAULTS: dict[str, Any] = {
    "active": True,
    "interval": 60,
    "maxretries": 2,
    "retryInterval": 60,
    "accepted_statuscodes": ["200-299"],
    "method": "GET",
    "maxredirects": 10,
    "ignoreTls": False,
    "upsideDown": False,
    "resendInterval": 0,
    "kafkaProducerBrokers": [],
    "kafkaProducerSaslOptions": {},
    "conditions": [],
    "rabbitmqNodes": [],
    "notificationIDList": {},
}


class SeedError(RuntimeError):
    """A step the instance refused; the message is Uptime Kuma's own."""


class MonitorClient(Protocol):
    """What the seed needs from a Uptime Kuma instance."""

    def connect(self) -> None:
        """Set up the admin account if the instance is fresh, then log in."""
        ...

    def monitors(self) -> Mapping[str, Mapping[str, Any]]:
        """Existing monitors, keyed by name."""
        ...

    def add_monitor(self, monitor: dict[str, Any]) -> int:
        """Create one monitor and return its id."""
        ...


class SocketIOClient:
    """The minimum Socket.IO v4 / Engine.IO v4 client the seed needs.

    Long-polling only: the transport is a pair of HTTP requests, so the whole
    client is a handshake, a POST queue and a GET that blocks until the server
    has something to say. The upgrade to WebSocket is refused by simply not
    asking for it.
    """

    def __init__(self, base_url: str, timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._http = httpx.Client(timeout=timeout)
        self._timeout = timeout
        self._sid = ""
        self._ack_id = 0
        self._acks: dict[int, list[Any]] = {}
        self._events: dict[str, Any] = {}
        self._connected = False

    def __enter__(self) -> SocketIOClient:
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    @property
    def url(self) -> str:
        return f"{self._base}/socket.io/?EIO=4&transport=polling&sid={self._sid}"

    def connect(self) -> None:
        response = self._http.get(f"{self._base}/socket.io/?EIO=4&transport=polling")
        response.raise_for_status()
        if not response.text.startswith("0"):
            raise SeedError(f"unexpected Engine.IO handshake: {response.text[:80]!r}")
        self._sid = str(json.loads(response.text[1:])["sid"])
        self._post("40")
        self.wait_for(lambda: self._connected, "the Socket.IO connect")

    def emit(self, event: str, *args: Any) -> Any:
        """Emit one event and return the first argument of its acknowledgement."""
        self._ack_id += 1
        ack_id = self._ack_id
        self._post(f"42{ack_id}{json.dumps([event, *args])}")
        self.wait_for(lambda: ack_id in self._acks, f"the {event!r} reply")
        reply = self._acks.pop(ack_id)
        return reply[0] if len(reply) == 1 else reply

    def event(self, name: str) -> Any:
        return self._events.get(name)

    def _post(self, payload: str) -> None:
        response = self._http.post(
            self.url,
            content=payload,
            headers={"Content-Type": "text/plain;charset=UTF-8"},
        )
        response.raise_for_status()
        if response.text not in ("", "ok"):
            for packet in response.text.split(PACKET_SEPARATOR):
                self._dispatch(packet)

    def _poll(self) -> None:
        response = self._http.get(self.url)
        response.raise_for_status()
        for packet in response.text.split(PACKET_SEPARATOR):
            self._dispatch(packet)

    def wait_for(self, done: Callable[[], bool], what: str) -> None:
        deadline = time.monotonic() + self._timeout
        while not done():
            if time.monotonic() >= deadline:
                raise SeedError(f"timed out waiting for {what}")
            self._poll()

    def _dispatch(self, packet: str) -> None:
        if packet == "2":  # Engine.IO ping: the client owns the pong.
            self._post("3")
            return
        if not packet.startswith("4"):  # open/close/pong carry nothing we use.
            return
        body = packet[1:]
        if body.startswith("0"):
            self._connected = True
        elif body.startswith("2"):
            ack_id, rest = _split_ack_id(body[1:])
            if ack_id is None:
                name, *args = json.loads(rest)
                self._events[name] = args[0] if len(args) == 1 else args
        elif body.startswith("3"):
            ack_id, rest = _split_ack_id(body[1:])
            if ack_id is not None:
                self._acks[ack_id] = list(json.loads(rest))
        elif body.startswith("4"):
            message = json.loads(body[1:]).get("message", body)
            raise SeedError(f"Socket.IO error: {message}")


def _split_ack_id(text: str) -> tuple[int | None, str]:
    digits = len(text) - len(text.lstrip("0123456789"))
    if digits == 0:
        return None, text
    return int(text[:digits]), text[digits:]


class UptimeKumaClient:
    """A ``MonitorClient`` backed by one logged-in Socket.IO connection."""

    def __init__(self, base_url: str, username: str, password: str, timeout: float = 30.0) -> None:
        self._socket = SocketIOClient(base_url, timeout=timeout)
        self._username = username
        self._password = password

    def __enter__(self) -> UptimeKumaClient:
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self._socket.close()

    def connect(self) -> None:
        self._socket.connect()
        if self._socket.emit("needSetup"):
            self._socket.emit("setup", self._username, self._password)
        reply = self._socket.emit("login", {"username": self._username, "password": self._password})
        if not reply.get("ok"):
            raise SeedError(f"login failed: {reply.get('msg', 'unknown reason')}")
        self._socket.wait_for(
            lambda: self._socket.event("monitorList") is not None, "the monitor list"
        )

    def monitors(self) -> Mapping[str, Mapping[str, Any]]:
        listed = self._socket.event("monitorList") or {}
        values = listed.values() if isinstance(listed, Mapping) else listed
        return {str(item["name"]): item for item in values}

    def add_monitor(self, monitor: dict[str, Any]) -> int:
        reply = self._socket.emit("add", monitor)
        if not reply.get("ok"):
            raise SeedError(f"add {monitor['name']!r} failed: {reply.get('msg', 'unknown reason')}")
        return int(reply["monitorID"])


def load_env_file(path: Path = ENV_FILE) -> dict[str, str]:
    """The repository ``.env``, read the way the other operator scripts read it."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def setting(name: str, default: str = "") -> str:
    """The process environment wins over ``.env``, which wins over ``default``."""
    return os.environ.get(name) or load_env_file().get(name) or default


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        spec: dict[str, Any] = json.load(handle)
    return spec


def monitor_payload(entry: Mapping[str, Any]) -> dict[str, Any]:
    """One ``monitors.json`` entry as the payload the ``add`` event takes."""
    return {
        **MONITOR_DEFAULTS,
        **{key: value for key, value in entry.items() if not key.startswith("_")},
    }


def seed(client: MonitorClient, spec: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """Create the missing monitors; return ``(added, kept)`` names."""
    # shortcut: existing monitors are not reconciled — a retuned monitor is
    # left alone rather than overwritten; upgrade to `editMonitor` if drift
    # between this file and the instance becomes a real problem.
    existing = client.monitors()
    added: list[str] = []
    kept: list[str] = []
    for entry in spec["monitors"]:
        name = str(entry["name"])
        if name in existing:
            kept.append(name)
            continue
        client.add_monitor(monitor_payload(entry))
        added.append(name)
    return added, kept


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=setting("UPTIME_KUMA_URL", DEFAULT_URL))
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--user", default=setting("UPTIME_KUMA_ADMIN_USER", "admin"))
    args = parser.parse_args(argv)

    password = setting("UPTIME_KUMA_ADMIN_PASSWORD")
    if not password:
        print("seed: set UPTIME_KUMA_ADMIN_PASSWORD in .env", file=sys.stderr)
        return 2

    spec = load_config(args.config)
    try:
        with UptimeKumaClient(args.url, args.user, password) as client:
            added, kept = seed(client, spec)
    except (SeedError, httpx.HTTPError) as error:
        print(f"seed: {error}", file=sys.stderr)
        return 1

    for name in added:
        print(f"added  {name}")
    for name in kept:
        print(f"kept   {name}")
    for entry in spec.get("unmonitored", []):
        print(f"unmonitored  {entry['service']}: {entry['reason']}")
    print(f"seed: {len(added)} added, {len(kept)} already present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
