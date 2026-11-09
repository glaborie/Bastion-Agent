"""Session-wide test bootstrap.

Loaded before any test module (and therefore before ``gateway.main`` imports and
builds the app), so the tracing exporter never runs during tests even when the
developer's ``.env`` enables it.
"""

from __future__ import annotations

import os

os.environ["OTEL_ENABLED"] = "false"
