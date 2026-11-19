"""Read a Compose-style ``.env`` file.

One assignment per line, with these rules:

* blank lines and lines whose first non-space character is ``#`` are ignored;
* an optional ``export `` prefix is dropped;
* the line splits at the first ``=``, and a line without one is ignored;
* the key is stripped and must match ``[A-Za-z_][A-Za-z0-9_]*``; any other key
  shape is ignored, which is the stricter of the two readers this replaces
  (IDEA-081 resolved that divergence deliberately);
* the value is stripped, then one matching pair of surrounding ``'`` or ``"``
  is removed;
* a repeated key takes its last value, and a missing or unreadable file reads as
  an empty mapping.

An inline comment after an unquoted value (``KEY=value # note``) stays part of
the value. That matches the two readers this module replaces, not full Compose
dotenv semantics (no escapes, no multi-line quoted values).
"""

from __future__ import annotations

import re
from pathlib import Path

KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def read_env(path: Path) -> dict[str, str]:
    """Parse ``path`` as a Compose-style ``.env``; see the module docstring."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].lstrip()
        key, separator, value = stripped.partition("=")
        if not separator:
            continue
        key = key.strip()
        if not KEY.fullmatch(key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values
