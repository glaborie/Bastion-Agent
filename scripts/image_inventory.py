#!/usr/bin/env python3
"""List every container image the compose stack can ship.

The scan set is derived from the compose files rather than maintained by hand,
so a new ``image:`` line is scanned without anyone remembering to add it. ``--compose``
is repeatable and the result is the additive union of every file given: the base
file plus an overlay is the stack a developer starts, and each overlay is parsed
on its own so a per-file ``${VAR:?}`` fails closed.

The parser expands ``${VAR}`` and ``${VAR:-default}`` the way Compose does, resolves
``<<: *anchor`` merges to the anchor's ``image:`` (``docker-compose.pki.yml``
declares its CA image that way), and gives a build-only service the final ``FROM``
of the Dockerfile its ``build:`` stanza names — the only image such a service
guarantees a scan can see. A ``${VAR:?message}`` with no value is an error, because
a scan of a half-rendered stack is worse than no scan.

``docker compose config --images`` is deliberately not used: rendering the files
requires every secret-shaped variable (``POSTGRES_PASSWORD``, ``VAULT_MASTER_KEY``
and the rest) and the CI job has no ``.env``. Parsing the same files gives the
same set with no secrets in the environment. A project ``.env`` is read the way
Compose reads it; the process environment wins over the file, and the file wins
over the ``${VAR:-default}`` fallback.

    uv run python scripts/image_inventory.py
    uv run python scripts/image_inventory.py --compose docker-compose.yml \
        --compose docker-compose.pki.yml
    uv run python scripts/image_inventory.py --compose docker-compose.yml --json
    uv run python scripts/image_inventory.py --slug postgres:16-alpine@sha256:...
    uv run python scripts/image_inventory.py --required-vars --compose docker-compose.pki.yml
    uv run python scripts/image_inventory.py --no-env-file
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path

# `python scripts/image_inventory.py` puts only `scripts/` on sys.path, so the
# repo root must be added for `scripts._env` to resolve as it does under pytest.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts._env import read_env  # pylint: disable=wrong-import-position

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_COMPOSE = ROOT / "docker-compose.yml"

IMAGE_LINE = re.compile(r"^\s*image:\s*(?P<ref>[^#\n]+?)\s*(?:#.*)?$")
SERVICE_HEADER = re.compile(r"^ {2}(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*):\s*$")
SECTION_HEADER = re.compile(r"^[A-Za-z0-9_.-]+:\s*$")
ANCHOR_HEADER = re.compile(r"^x-[A-Za-z0-9_.-]+:\s*&(?P<name>[A-Za-z0-9_.-]+)\s*$")
MERGE_ALIAS = re.compile(r"\*(?P<name>[A-Za-z0-9_.-]+)")
ALIAS_REF = re.compile(r"^\*(?P<name>[A-Za-z0-9_.-]+)$")
FROM_LINE = re.compile(r"^[ \t]*FROM[ \t]+(?P<ref>[^\s#]+)", re.IGNORECASE | re.MULTILINE)
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


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _sections(text: str) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Top-level ``x-`` anchors and the ``services:`` blocks, in file order."""
    anchors: dict[str, list[str]] = {}
    services: dict[str, list[str]] = {}
    anchor: str | None = None
    service: str | None = None
    in_services = False
    for line in text.splitlines():
        header = ANCHOR_HEADER.match(line)
        if header is not None:
            anchor_name = header.group("name")
            anchor, service, in_services = anchor_name, None, False
            anchors[anchor_name] = []
            continue
        if SECTION_HEADER.match(line):
            anchor, service, in_services = None, None, line.strip() == "services:"
            continue
        if anchor is not None:
            anchors[anchor].append(line)
            continue
        if not in_services:
            continue
        match = SERVICE_HEADER.match(line)
        if match is not None:
            service_name = match.group("name")
            service = service_name
            services[service_name] = []
        elif service is not None and line.strip():
            services[service].append(line)
    return anchors, services


#: Controls that run behind a profile but are not part of the shipped stack.
#: The Trivy scanner and Falco are tooling around it; the MinIO witness store is
#: a service the compliance profile actually serves from, so it stays in the SBOM
#: and the image scan.
_TOOLING_SERVICES = frozenset({"trivy-scan", "falco"})


def _image_ref(body: list[str]) -> str | None:
    """The service's or anchor's own ``image:`` value, if it declares one."""
    for line in body:
        if line.lstrip().startswith("#"):
            continue
        match = IMAGE_LINE.match(line)
        if match is not None:
            return match.group("ref").strip()
    return None


def _anchor_images(anchors: dict[str, list[str]], env: dict[str, str]) -> dict[str, str]:
    images: dict[str, str] = {}
    for name, body in anchors.items():
        ref = _image_ref(body)
        if ref is not None:
            images[name] = expand(ref, env)
    return images


def _merged_image(body: list[str], inherited: dict[str, str]) -> str | None:
    """The image inherited through ``<<: *anchor``, if the anchor carries one."""
    for line in body:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped.startswith("<<:"):
            continue
        for match in MERGE_ALIAS.finditer(stripped):
            image = inherited.get(match.group("name"))
            if image is not None:
                return image
    return None


def _dockerfile_base(body: list[str], path: Path) -> str | None:
    """The final ``FROM`` of a build-only service's Dockerfile.

    Only a stanza that names its Dockerfile contributes a reference: without one
    the service builds an image another file already declares (the GPU overlay
    rebuilds the ``bastion-agent`` image with ``target: runtime-gpu``).
    """
    context = "."
    dockerfile: str | None = None
    indent: int | None = None
    for line in body:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        current = _indent(line)
        if indent is None:
            key, _, value = stripped.partition(":")
            if key == "build" and current > 2:
                indent = current
                if value.strip():
                    context = value.strip()
            continue
        if current <= indent:
            indent = None
            continue
        key, _, value = stripped.partition(":")
        if key == "dockerfile":
            dockerfile = value.strip()
        elif key == "context":
            context = value.strip()
    if dockerfile is None:
        return None
    candidate = path.parent / context / dockerfile
    try:
        text = candidate.read_text(encoding="utf-8")
    except OSError as exc:
        raise InventoryError(
            f"cannot read the Dockerfile of a build-only service: {candidate}"
        ) from exc
    refs = [match.group("ref") for match in FROM_LINE.finditer(text)]
    if not refs:
        raise InventoryError(f"no FROM line in {candidate}")
    return None if refs[-1] == "scratch" else refs[-1]


def read_images(
    paths: Sequence[Path] = (DEFAULT_COMPOSE,),
    env: dict[str, str] | None = None,
    env_file: Path | None = None,
) -> list[str]:
    """Return the additive, de-duplicated image set of every file, in file order."""
    if env is None:
        environment = read_env(env_file) if env_file is not None else {}
        environment.update(os.environ)
    else:
        environment = dict(env)

    images: list[str] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise InventoryError(f"cannot read {path}: {exc}") from exc
        anchors, services = _sections(text)
        inherited = _anchor_images(anchors, environment)
        for name, body in services.items():
            if name in _TOOLING_SERVICES:
                continue
            ref = _image_ref(body) or _merged_image(body, inherited)
            if ref is None:
                ref = _dockerfile_base(body, path)
            if ref is None:
                continue
            alias = ALIAS_REF.match(ref)
            if alias is not None:
                target = inherited.get(alias.group("name"))
                if target is None:
                    raise InventoryError(f"{path}: image reference uses unknown anchor: {ref}")
                image = target
            else:
                image = expand(ref, environment)
            if image not in images:
                images.append(image)

    if not images:
        raise InventoryError(
            f"no image references found in {', '.join(str(path) for path in paths)}"
        )
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
    parser.add_argument(
        "--compose",
        type=Path,
        action="append",
        metavar="FILE",
        help="compose file to read; repeat to add an overlay (default: docker-compose.yml)",
    )
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
        help="print the ${NAME:?} variables the files require",
    )
    args = parser.parse_args(argv)

    if args.slug:
        print(slug(args.slug))
        return 0

    env_file = args.env_file
    if env_file is None and not args.no_env_file:
        candidate = ROOT / ".env"
        env_file = candidate if candidate.is_file() else None
    paths: list[Path] = list(args.compose or [DEFAULT_COMPOSE])

    try:
        if args.required_vars:
            names: set[str] = set()
            for path in paths:
                names.update(required_vars(path.read_text(encoding="utf-8")))
            for name in sorted(names):
                print(name)
            return 0
        images = read_images(paths, env_file=env_file)
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
