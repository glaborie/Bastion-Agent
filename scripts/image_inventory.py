#!/usr/bin/env python3
"""List every container image the compose stack can ship.

The scan set is derived from ``docker-compose.yml`` rather than maintained by
hand, so a new ``image:`` line is scanned without anyone remembering to add it.
The parser expands ``${VAR}`` and ``${VAR:-default}`` the way Compose does; a
``${VAR:?message}`` with no value is an error, because a scan of a half-rendered
stack is worse than no scan.

``docker compose config --images`` is deliberately not used: rendering the file
requires every secret-shaped variable (``POSTGRES_PASSWORD``, ``VAULT_MASTER_KEY``
and seven others) and the CI job has no ``.env``. Parsing the same file gives the
same set with no secrets in the environment. A project ``.env`` is read the way
Compose reads it; the process environment wins over the file, and the file wins
over the ``${VAR:-default}`` fallback.

    uv run python scripts/image_inventory.py
    uv run python scripts/image_inventory.py --compose docker-compose.yml --json
    uv run python scripts/image_inventory.py --slug postgres:16-alpine@sha256:...
    uv run python scripts/image_inventory.py --required-vars
    uv run python scripts/image_inventory.py --no-env-file
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_COMPOSE = ROOT / "docker-compose.yml"

IMAGE_LINE = re.compile(r"^\s*image:\s*(?P<ref>[^#\n]+?)\s*(?:#.*)?$")
SERVICE_HEADER = re.compile(r"^ {2}(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*):\s*$")
PROFILES_LINE = re.compile(r"^\s+profiles:\s*\[(?P<profiles>[^\]]*)\]\s*$")
VAR_REF = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::-(?P<default>[^}]*))?\}")
REQUIRED_REF = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*):\?")


class InventoryError(RuntimeError):
    """The compose file cannot be turned into a complete image list."""


def required_vars(text: str) -> list[str]:
    """Names used as ``${NAME:?message}`` anywhere in the file."""
    return sorted({match.group("name") for match in REQUIRED_REF.finditer(text)})


def expand(ref: str, env: dict[str, str]) -> str:
    """Expand Compose-style variable references in one image reference."""

    def replace(match: re.Match[str]) -> str:
        name = match.group("name")
        default = match.group("default")
        value = env.get(name)
        if value:
            return value
        if default is not None:
            return default
        raise InventoryError(f"image reference needs ${name}, which is not set: {ref}")

    expanded = VAR_REF.sub(replace, ref)
    if "$" in expanded:
        raise InventoryError(f"unsupported variable syntax in image reference: {ref}")
    return expanded


def _blocks(text: str) -> list[tuple[str, list[str]]]:
    """Split the file into compose service blocks (and top-level anchors)."""
    blocks: list[tuple[str, list[str]]] = []
    name: str | None = None
    body: list[str] = []
    for line in text.splitlines():
        match = SERVICE_HEADER.match(line)
        if match is not None:
            if name is not None:
                blocks.append((name, body))
            name = match.group("name")
            body = []
        elif name is not None:
            body.append(line)
    if name is not None:
        blocks.append((name, body))
    return blocks


def _is_scanner_only(body: list[str]) -> bool:
    """True when a service exists only behind the compliance profile.

    The Trivy scanner is tooling, not a shipped image: it is digest-pinned and
    excluded from the SBOM so the artifact describes what the stack serves.
    """
    for line in body:
        match = PROFILES_LINE.match(line)
        if match is not None:
            profiles = {item.strip() for item in match.group("profiles").split(",")}
            return profiles == {"compliance"}
    return False


def read_env_file(path: Path) -> dict[str, str]:
    """Read a Compose-style ``.env``: KEY=VALUE, optional quotes, # comments."""
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
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def read_images(
    path: Path = DEFAULT_COMPOSE,
    env: dict[str, str] | None = None,
    env_file: Path | None = None,
) -> list[str]:
    """Return image references in file order, de-duplicated."""
    if env is None:
        environment = read_env_file(env_file) if env_file is not None else {}
        environment.update(os.environ)
    else:
        environment = dict(env)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InventoryError(f"cannot read {path}: {exc}") from exc

    images: list[str] = []
    for _name, body in _blocks(text):
        if _is_scanner_only(body):
            continue
        for line in body:
            if line.lstrip().startswith("#"):
                continue
            match = IMAGE_LINE.match(line)
            if match is None:
                continue
            image = expand(match.group("ref").strip(), environment)
            if image not in images:
                images.append(image)
            break

    if not images:
        raise InventoryError(f"no image references found in {path}")
    return images


def slug(image: str) -> str:
    """A filename-safe, stable key for one image reference.

    ``postgres:16-alpine@sha256:...`` -> ``postgres-16-alpine``;
    ``ghcr.io/x/y:z`` -> ``ghcr.io-x-y-z``.
    """
    without_digest = image.split("@", 1)[0]
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", without_digest.lower()).strip("-")
    return cleaned or "image"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", type=Path, default=DEFAULT_COMPOSE)
    parser.add_argument("--json", action="store_true", help="print a JSON object")
    parser.add_argument("--slug", metavar="IMAGE", help="print the slug for one reference")
    parser.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="read variable fallbacks from this file (default: ./.env if present)",
    )
    parser.add_argument(
        "--no-env-file",
        action="store_true",
        help="ignore ./.env and use only the process environment and Compose defaults",
    )
    parser.add_argument(
        "--required-vars",
        action="store_true",
        help="print the ${NAME:?} variables the file requires",
    )
    args = parser.parse_args(argv)

    if args.slug:
        print(slug(args.slug))
        return 0

    env_file = args.env_file
    if env_file is None and not args.no_env_file:
        candidate = ROOT / ".env"
        env_file = candidate if candidate.is_file() else None

    try:
        text = args.compose.read_text(encoding="utf-8")
        if args.required_vars:
            for name in required_vars(text):
                print(name)
            return 0
        images = read_images(args.compose, env_file=env_file)
    except (InventoryError, OSError) as exc:
        print(f"image-inventory: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"images": images}, indent=2))
    else:
        for image in images:
            print(image)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
