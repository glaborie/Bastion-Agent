"""The OmniRoute data volume must sit where the image keeps its SQLite store."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_the_data_volume_mounts_at_the_images_data_dir() -> None:
    """3.8.53 sets ``DATA_DIR=/app/data``; anywhere else persists nothing.

    The volume was mounted at /root/.omniroute for two days while the app wrote
    /app/data, so every recreated container came up with no keys and the gateway
    answered 401 AUTH_002.
    """
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))

    assert "omniroute_data:/app/data" in compose["services"]["omniroute"]["volumes"]
