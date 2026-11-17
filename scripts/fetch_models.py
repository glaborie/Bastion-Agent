#!/usr/bin/env python3
"""Fetch and verify the pinned ONNX guard graphs into ``models/`` (ADR-011).

The compose stack mounts ``./models`` into gateway and worker read-only, and
nothing created the two graphs before this script: a checkout that skipped the
manual ``hf download`` started the gateway into a ``ClassifierConfigurationError``
(IDEA-064). ``models-init`` now runs this fetcher before those services, and
``make models`` runs it on the host for tests that need the real graph.

Both repositories are pinned by revision and the downloaded graph is verified
against the SHA-256 the classifier verifies at load time, so a cached or partial
download cannot silently become the decision model. Files are written to a
temporary sibling and moved into place only after the digest matches, so a
failed fetch leaves no half graph behind.

    uv run python scripts/fetch_models.py [--check] [--root DIR]

Exit codes: ``0`` both graphs present and verified, ``1`` a fetch failed, ``2``
a configured digest is missing or a downloaded graph does not match it.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HF_BASE = "https://huggingface.co"
#: The same revisions CI downloads (``.github/workflows/ci.yml``). Bumping one is
#: a code change: the digest in settings must move with it.
INJECTION_REPO = "Horizon-Labs/prompt-injection-guard-small"
INJECTION_REVISION = "2efc2ed5abecd21eb45c2506d231a65d6e392b85"
SAFETY_REPO = "onnx-community/content-safety-guard-small-ONNX"
SAFETY_REVISION = "74e953e4b14199e152899135cb176a0998135baf"
GRAPH_FILE = "onnx/model_quantized.onnx"
SIDECARS = ("tokenizer.json", "config.json")


@dataclass(frozen=True, slots=True)
class Guard:
    """One pinned guard repository and the settings that point at it."""

    name: str
    repo: str
    revision: str
    model_path: str | None
    digest: str | None


class FetchError(RuntimeError):
    """A fetch or verification failed; the message names the file, never bytes."""


def sha256_of(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def download_url(repo: str, revision: str, name: str) -> str:
    return f"{HF_BASE}/{repo}/resolve/{revision}/{name}"


def fetch(url: str, destination: Path, *, token: str | None = None) -> int:
    """Stream ``url`` next to ``destination`` and return the bytes written."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    handle, temporary = tempfile.mkstemp(dir=destination.parent, suffix=".part")
    try:
        with (
            os.fdopen(handle, "wb") as sink,
            urllib.request.urlopen(request, timeout=120) as source,
        ):
            written = 0
            for block in iter(lambda: source.read(1024 * 1024), b""):
                sink.write(block)
                written += len(block)
        os.replace(temporary, destination)
        return written
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def ensure(guard: Guard, root: Path, *, token: str | None = None) -> bool:
    """Materialise one guard's graph and sidecars. Returns True if it fetched."""
    if guard.model_path is None:
        print(f"{guard.name}: no model path configured, rule fallback in use")
        return False
    if not guard.digest:
        raise FetchError(
            f"{guard.name}: no pinned digest configured; refusing to fetch an unverified graph"
        )
    model = root / guard.model_path
    if model.is_file() and sha256_of(model) == guard.digest:
        print(f"{guard.name}: {model} verified")
        return False
    expected = guard.digest
    if model.is_file():
        raise FetchError(
            f"{guard.name}: {model} digest mismatch: expected {expected}, got {sha256_of(model)}"
        )
    base = model.parent.parent
    written = fetch(download_url(guard.repo, guard.revision, GRAPH_FILE), model, token=token)
    actual = sha256_of(model)
    if actual != expected:
        model.unlink(missing_ok=True)
        raise FetchError(
            f"{guard.name}: {model} digest mismatch: expected {expected}, got {actual}"
        )
    for sidecar in SIDECARS:
        if not (base / sidecar).is_file():
            fetch(download_url(guard.repo, guard.revision, sidecar), base / sidecar, token=token)
    print(f"{guard.name}: fetched {model} ({written} bytes), digest verified")
    return True


def guards_from_settings() -> Iterable[Guard]:
    from settings import get_settings

    settings = get_settings()
    yield Guard(
        name="injection-guard",
        repo=INJECTION_REPO,
        revision=INJECTION_REVISION,
        model_path=settings.classifier_injection_model_path,
        digest=settings.classifier_injection_model_sha256,
    )
    yield Guard(
        name="safety-guard",
        repo=SAFETY_REPO,
        revision=SAFETY_REVISION,
        model_path=settings.classifier_safety_model_path,
        digest=settings.classifier_safety_model_sha256,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch and verify the ONNX guard graphs.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify only: fail when a graph is missing instead of downloading it",
    )
    parser.add_argument(
        "--root", type=Path, default=ROOT, help="directory the settings paths are relative to"
    )
    args = parser.parse_args(argv)
    token = os.environ.get("HF_TOKEN") or None

    fetched = 0
    for guard in guards_from_settings():
        if args.check:
            if guard.model_path and guard.digest:
                model = args.root / guard.model_path
                if not model.is_file() or sha256_of(model) != guard.digest:
                    raise FetchError(
                        f"{guard.name}: {model} is missing or does not match its digest"
                    )
                print(f"{guard.name}: {model} verified")
            continue
        fetched += int(ensure(guard, args.root, token=token))
    if not args.check:
        print(f"models: {'fetched ' + str(fetched) if fetched else 'nothing to fetch'}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FetchError as error:
        print(f"fetch_models: {error}", file=sys.stderr)
        sys.exit(2)
    except OSError as error:
        print(f"fetch_models: {error}", file=sys.stderr)
        sys.exit(1)
