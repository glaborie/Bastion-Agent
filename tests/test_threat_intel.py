"""Dependency threat-intelligence audit (OSV over uv.lock)."""

# pylint: disable=protected-access  # tests assert the advisory field extractors

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "update_threat_intel.py"


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("update_threat_intel", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


threat_intel = load_script()


def write_lock(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_parse_lockfile_keeps_registry_packages_only(tmp_path: Path) -> None:
    lock = write_lock(
        tmp_path / "uv.lock",
        """
[[package]]
name = "demo-lib"
version = "1.2.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "bastion-agent"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "url-wheel"
version = "9.9.9"
source = { url = "https://example.invalid/pkg.whl" }
""",
    )
    assert threat_intel.parse_lockfile(lock) == [("demo-lib", "1.2.3")]


def test_parse_lockfile_rejects_an_empty_lock(tmp_path: Path) -> None:
    lock = write_lock(tmp_path / "uv.lock", "version = 1\n")
    with pytest.raises(threat_intel.AuditError, match="no registry packages"):
        threat_intel.parse_lockfile(lock)


def test_parse_lockfile_rejects_invalid_toml(tmp_path: Path) -> None:
    lock = write_lock(tmp_path / "uv.lock", "[[package]\n")
    with pytest.raises(threat_intel.AuditError, match="cannot read"):
        threat_intel.parse_lockfile(lock)


def test_evaluate_matches_ids_and_aliases() -> None:
    findings = [
        {"id": "GHSA-1111", "aliases": []},
        {"id": "GHSA-2222", "aliases": ["CVE-2026-2222"]},
    ]
    blocking, accepted = threat_intel.evaluate(findings, {"CVE-2026-2222"})
    assert [finding["id"] for finding in blocking] == ["GHSA-1111"]
    assert [finding["id"] for finding in accepted] == ["GHSA-2222"]


def test_severity_uses_only_published_labels() -> None:
    assert threat_intel._severity({"database_specific": {"severity": "high"}}) == "HIGH"
    assert (
        threat_intel._severity({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/..."}]})
        == "UNRATED"
    )


def test_fixed_versions_are_scoped_to_the_package() -> None:
    vulnerability = {
        "affected": [
            {
                "package": {"name": "demo"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
            },
            {
                "package": {"name": "other"},
                "ranges": [{"events": [{"fixed": "9.9.9"}]}],
            },
        ]
    }
    assert threat_intel._fixed_versions(vulnerability, "demo") == ["1.2.3"]


def write_report(path: Path, findings: list[dict[str, object]]) -> Path:
    path.write_text(json.dumps({"packages": 3, "findings": findings}), encoding="utf-8")
    return path


def test_offline_report_with_a_finding_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(
        tmp_path / "report.json",
        [{"id": "GHSA-x", "package": "demo", "version": "1.0", "aliases": []}],
    )
    assert threat_intel.main(["--offline", str(report), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["blocking"][0]["id"] == "GHSA-x"


def test_offline_report_passes_when_the_finding_is_ignored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = write_report(
        tmp_path / "report.json",
        [{"id": "GHSA-x", "package": "demo", "version": "1.0", "aliases": ["CVE-1"]}],
    )
    assert threat_intel.main(["--offline", str(report), "--ignore", "CVE-1"]) == 0
    assert "OK: no unignored vulnerabilities." in capsys.readouterr().out


def test_offline_rejects_a_malformed_report(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text('{"not": "a report"}', encoding="utf-8")
    assert threat_intel.main(["--offline", str(report)]) == 2


def test_offline_missing_report_is_an_error(tmp_path: Path) -> None:
    assert threat_intel.main(["--offline", str(tmp_path / "missing.json")]) == 2
