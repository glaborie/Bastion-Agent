"""PDF ingestion: redaction before the text can reach a model (ADR-023)."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fakeredis import FakeAsyncRedis

from agent.dlp.presidio import PresidioDLP, get_analyzer
from agent.dlp.vault import TokenVault
from agent.ingest import cli, document
from agent.ingest.document import (
    IngestError,
    MarkItDownExtractor,
    ingest,
    restore,
    session_for,
)
from settings import Settings, get_settings

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "data" / "documents" / "dossier.pdf"
BLANK = ROOT / "tests" / "data" / "documents" / "blank.pdf"
AUTHOR = "Tobias Beispiel"
TITLE = "Employee record 2026"
PLAINTEXT = ("Maria Keller", "maria.keller@example.com", "CH93 0076 2011 6238 5295 7")
KEY = b"i" * 32


def _dlp(ttl: int = 600) -> tuple[PresidioDLP, TokenVault]:
    vault = TokenVault(FakeAsyncRedis(decode_responses=True), key=KEY, ttl_seconds=ttl)
    return PresidioDLP(vault, analyzer=get_analyzer()), vault


async def _ingest_fixture() -> tuple[str, document.IngestReport, PresidioDLP]:
    dlp, _vault = _dlp()
    text, report = await ingest(FIXTURE, tenant_id="acme", actor_id="alice", dlp=dlp)
    return text, report, dlp


def _run_cli(monkeypatch: pytest.MonkeyPatch, argv: list[str], dlp: PresidioDLP) -> int:
    monkeypatch.setattr(cli, "get_dlp", lambda: dlp)
    return cli.main(argv)


async def test_a_pdf_is_redacted_and_carries_no_metadata(tmp_path: Path) -> None:
    text, report, _dlp_instance = await _ingest_fixture()

    assert "{{ENTITY:PERSON_1}}" in text
    assert "{{ENTITY:EMAIL_ADDRESS_1}}" in text
    assert "{{ENTITY:IBAN_CODE_1}}" in text
    for value in PLAINTEXT:
        assert value not in text
    assert AUTHOR not in text
    assert TITLE not in text
    assert report.pages == 1
    assert report.extractor == "markitdown"


def _encrypted_fixture(tmp_path: Path) -> Path:
    payload = FIXTURE.read_bytes().replace(b"/Info 6 0 R", b"/Info 6 0 R /Encrypt 7 0 R")
    path = tmp_path / "encrypted.pdf"
    path.write_bytes(payload)
    return path


@pytest.mark.parametrize(
    ("name", "payload", "expected"),
    [
        ("encrypted", "encrypted", "encrypted"),
        ("truncated", b"%PDF-1.4\ntrailer\n", "could not be parsed"),
        ("mislabelled", b"\x89PNG\r\n\x1a\n" + b"0" * 100, "magic number"),
        ("blank", "blank", "no text"),
    ],
)
def test_fail_closed_cases_write_no_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    payload: Any,
    expected: str,
) -> None:
    if payload == "encrypted":
        source = _encrypted_fixture(tmp_path)
    elif payload == "blank":
        source = BLANK
    else:
        source = tmp_path / f"{name}.pdf"
        source.write_bytes(payload)
    output = tmp_path / "artifact.md"
    output.write_text("keep me", encoding="utf-8")
    dlp, _vault = _dlp()

    code = _run_cli(
        monkeypatch,
        ["convert", str(source), "--tenant", "acme", "--actor", "alice", "--output", str(output)],
        dlp,
    )

    assert code != 0
    assert output.read_text(encoding="utf-8") == "keep me"


def test_an_oversized_file_is_refused_before_the_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "artifact.md"
    dlp, _vault = _dlp()
    monkeypatch.setattr(
        document, "get_settings", lambda: Settings(_env_file=None, document_max_bytes=100)
    )

    code = _run_cli(
        monkeypatch,
        ["convert", str(FIXTURE), "--tenant", "acme", "--actor", "alice", "--output", str(output)],
        dlp,
    )

    assert code != 0
    assert not output.exists()


def test_a_slow_extractor_times_out_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SlowExtractor:
        name = "slow"

        def convert(self, data: bytes) -> str:
            time.sleep(2)
            return "text"

    output = tmp_path / "artifact.md"
    dlp, _vault = _dlp()
    monkeypatch.setattr(document, "MarkItDownExtractor", SlowExtractor)
    monkeypatch.setattr(
        document,
        "get_settings",
        lambda: Settings(_env_file=None, document_parse_timeout_seconds=1),
    )

    code = _run_cli(
        monkeypatch,
        ["convert", str(FIXTURE), "--tenant", "acme", "--actor", "alice", "--output", str(output)],
        dlp,
    )

    assert code != 0
    assert not output.exists()


def test_the_adapter_is_closed_and_cannot_reach_a_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: list[dict[str, Any]] = []

    class Recorder:
        def __init__(self, **kwargs: Any) -> None:
            recorded.append(kwargs)

        def convert_stream(self, *_args: Any, **_kwargs: Any) -> Any:
            return type("Result", (), {"text_content": "text"})()

    monkeypatch.setattr(document, "MarkItDown", Recorder)

    MarkItDownExtractor()

    assert recorded == [{"enable_plugins": False}]
    fields = set(Settings.model_fields)
    assert not {name for name in fields if "docintel" in name or name == "llm_client"}


async def test_conversion_makes_no_network_request(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def refuse(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
        calls.append(str(request))
        raise AssertionError("the ingestion path opened a network connection")

    monkeypatch.setattr(httpx.Client, "send", refuse)
    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)
    dlp, _vault = _dlp()

    await ingest(FIXTURE, tenant_id="acme", actor_id="alice", dlp=dlp)

    assert not calls


async def test_the_shipped_redactor_produces_the_same_markers() -> None:
    raw = MarkItDownExtractor().convert(FIXTURE.read_bytes())
    dlp, _vault = _dlp()
    session = session_for("acme", "alice", FIXTURE.read_bytes())

    text, _report = await ingest(FIXTURE, tenant_id="acme", actor_id="alice", dlp=dlp)
    direct = await dlp.redact(raw, session, tenant_id="acme")

    assert text == direct.text


async def test_logs_carry_counts_not_values(caplog: pytest.LogCaptureFixture) -> None:
    dlp, _vault = _dlp()
    with caplog.at_level(logging.INFO):
        await ingest(FIXTURE, tenant_id="acme", actor_id="alice", dlp=dlp)

    logged = "\n".join(f"{record.msg} {record.args}" for record in caplog.records)
    for value in PLAINTEXT:
        assert value not in logged
    assert "document ingested" in logged


async def test_restore_is_scoped_to_the_tenant_and_session() -> None:
    dlp, _vault = _dlp()
    text, report = await ingest(FIXTURE, tenant_id="acme", actor_id="alice", dlp=dlp)

    restored, expired = await restore(text, tenant_id="acme", session_id=report.session_id, dlp=dlp)
    assert expired == 0
    assert "maria.keller@example.com" in restored

    other_tenant, _ = await restore(text, tenant_id="globex", session_id=report.session_id, dlp=dlp)
    assert other_tenant == text
    other_session, _ = await restore(text, tenant_id="acme", session_id="ingest:other", dlp=dlp)
    assert other_session == text


async def test_expired_markers_are_reported_not_restored() -> None:
    dlp, _vault = _dlp(ttl=1)
    text, report = await ingest(FIXTURE, tenant_id="acme", actor_id="alice", dlp=dlp)
    await asyncio.sleep(1.4)

    restored, expired = await restore(text, tenant_id="acme", session_id=report.session_id, dlp=dlp)

    assert expired > 0
    assert "{{ENTITY:" in restored
    assert "maria.keller@example.com" not in restored


def test_the_dependency_is_the_narrow_pdf_extra() -> None:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "markitdown[pdf]" in project
    assert "markitdown[all]" not in project


def test_no_gateway_surface_ships_with_it() -> None:
    surface = [
        ROOT / "docs" / "tools" / "v1.json",
        ROOT / "docker-compose.yml",
        *sorted((ROOT / "gateway").rglob("*.py")),
    ]
    for path in surface:
        assert "markitdown" not in path.read_text(encoding="utf-8"), path


def test_the_readme_states_the_boundary() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "De-identification is not declassification" in readme
    assert "ADR-023" in readme
    settings_fields = set(Settings.model_fields)
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for field in ("document_max_bytes", "document_parse_timeout_seconds"):
        assert field in settings_fields
        assert field.upper() in env_example


def test_an_encrypted_pdf_is_refused_by_name(tmp_path: Path) -> None:
    source = _encrypted_fixture(tmp_path)

    with pytest.raises(IngestError, match="encrypted"):
        document.validate(source.read_bytes(), source, max_bytes=10_000_000)


def test_the_settings_ceiling_is_documented_in_the_model() -> None:
    settings = get_settings()
    assert settings.document_max_bytes > 0
    assert settings.document_parse_timeout_seconds > 0


def test_a_renamed_png_fails_on_the_magic_number(tmp_path: Path) -> None:
    source = tmp_path / "photo.pdf"
    source.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)

    with pytest.raises(IngestError, match="magic number"):
        document.validate(source.read_bytes(), source, max_bytes=10_000_000)
