"""The models-init fetcher and its compose wiring (IDEA-064, ADR-011)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from scripts import fetch_models

ROOT = Path(__file__).resolve().parents[1]
GOOD = b"int8-graph-bytes"
GOOD_SHA = hashlib.sha256(GOOD).hexdigest()


def _guard(model_path: str | None, digest: str | None) -> fetch_models.Guard:
    return fetch_models.Guard(
        name="injection-guard",
        repo=fetch_models.INJECTION_REPO,
        revision=fetch_models.INJECTION_REVISION,
        model_path=model_path,
        digest=digest,
    )


def _write_model(root: Path, payload: bytes = GOOD) -> Path:
    path = root / "models" / "guard" / "onnx" / "model_quantized.onnx"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def test_a_verified_graph_is_kept_without_a_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_model(tmp_path)
    guard = _guard("models/guard/onnx/model_quantized.onnx", GOOD_SHA)

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a verified graph was downloaded again")

    monkeypatch.setattr(fetch_models, "fetch", refuse)

    assert fetch_models.ensure(guard, tmp_path) is False


def test_a_fetched_graph_is_readable_by_the_container_uid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """mkstemp hands back 0600 and os.replace keeps it; the app runs as uid 10001."""
    guard = _guard("models/guard/onnx/model_quantized.onnx", GOOD_SHA)

    def fake_fetch(url: str, destination: Path, *, token: str | None = None) -> int:
        del url, token
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(GOOD)
        destination.chmod(0o600)
        return len(GOOD)

    monkeypatch.setattr(fetch_models, "fetch", fake_fetch)

    assert fetch_models.ensure(guard, tmp_path) is True
    for name in (
        "models/guard/onnx/model_quantized.onnx",
        "models/guard/tokenizer.json",
        "models/guard/config.json",
    ):
        assert (tmp_path / name).stat().st_mode & 0o777 == 0o644, name


def test_a_mismatched_digest_names_the_path_and_both_hashes(tmp_path: Path) -> None:
    model = _write_model(tmp_path, b"swapped-graph")
    guard = _guard("models/guard/onnx/model_quantized.onnx", GOOD_SHA)

    with pytest.raises(fetch_models.FetchError) as caught:
        fetch_models.ensure(guard, tmp_path)

    message = str(caught.value)
    assert str(model) in message
    assert GOOD_SHA in message
    assert hashlib.sha256(b"swapped-graph").hexdigest() in message


def test_a_missing_graph_is_fetched_from_the_pinned_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _guard("models/guard/onnx/model_quantized.onnx", GOOD_SHA)
    calls: list[str] = []

    def fake_fetch(url: str, destination: Path, *, token: str | None = None) -> int:
        calls.append(url)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(GOOD)
        return len(GOOD)

    monkeypatch.setattr(fetch_models, "fetch", fake_fetch)

    assert fetch_models.ensure(guard, tmp_path) is True
    pinned = (
        f"https://huggingface.co/{fetch_models.INJECTION_REPO}"
        f"/resolve/{fetch_models.INJECTION_REVISION}/onnx/model_quantized.onnx"
    )
    assert calls[0] == pinned
    assert len(calls) == 1 + len(fetch_models.SIDECARS)
    assert (tmp_path / "models/guard/tokenizer.json").is_file()


def test_a_failed_download_leaves_no_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "models" / "guard" / "onnx" / "model_quantized.onnx"

    def offline(*_args: object, **_kwargs: object) -> None:
        raise OSError("network is unreachable")

    monkeypatch.setattr(fetch_models.urllib.request, "urlopen", offline)

    with pytest.raises(OSError):
        fetch_models.fetch("https://huggingface.co/repo/file", destination)

    assert not list(tmp_path.rglob("*.part"))
    assert not destination.exists()


def test_a_guard_without_a_digest_is_refused(tmp_path: Path) -> None:
    guard = _guard("models/guard/onnx/model_quantized.onnx", None)

    with pytest.raises(fetch_models.FetchError, match="no pinned digest"):
        fetch_models.ensure(guard, tmp_path)


def test_the_stack_waits_for_the_models_before_the_app_starts() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]

    init = services["models-init"]
    assert init["entrypoint"] == ["python", "scripts/fetch_models.py"]
    assert "./models:/app/models" in init["volumes"]
    for service in ("gateway", "worker"):
        dependency = services[service]["depends_on"]["models-init"]
        assert dependency["condition"] == "service_completed_successfully"
