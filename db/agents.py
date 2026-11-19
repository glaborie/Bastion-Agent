"""The declarative agent-registry mirror (ADR-027).

The database row is the runtime source of truth; this file is what a reviewer
diffs and what the one-shot ``migrate`` service seeds missing rows from. It is
read by ``scripts/validate_rbac.py`` and never by a request path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

#: The registry seed; relative to the repository root like the tool catalog.
REGISTRY_SEED_PATH: Final[Path] = Path("config/agents/registry.json")


def load_registry_seed(path: Path = REGISTRY_SEED_PATH) -> list[dict[str, Any]]:
    """Parse the registry mirror; raises ``ValueError`` when malformed."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    agents = payload.get("agents") if isinstance(payload, dict) else None
    if not isinstance(agents, list):
        raise ValueError(f"{path} has no 'agents' list")
    entries: list[dict[str, Any]] = []
    for raw in agents:
        if not isinstance(raw, dict) or not isinstance(raw.get("agent_id"), str):
            raise ValueError(f"{path} has an entry without a string agent_id")
        entries.append(raw)
    return entries
