#!/usr/bin/env python3
"""Refresh dependency threat intelligence from OSV and gate on known CVEs.

The threat-intel feed has a single, well-defined source today: every package in
``uv.lock`` is queried against the [OSV](https://osv.dev) database for the PyPI
ecosystem. This covers the CVE/Snyk/GitHub-advisory slice of the threat model
without scraping or guessing; ATLAS/OWASP review stays a manual exercise.

    uv run python scripts/update_threat_intel.py                 # audit + write report
    uv run python scripts/update_threat_intel.py --ignore GHSA-x # accepted risk
    uv run python scripts/update_threat_intel.py --offline artifacts/threat-intel/latest.json

Exit codes: ``0`` no unignored findings, ``1`` findings, ``2`` the audit could
not run (bad lockfile/report, network failure). ``--offline`` evaluates a saved
report, so CI can gate without network access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
ECOSYSTEM = "PyPI"
BATCH_SIZE = 500
DEFAULT_LOCKFILE = Path("uv.lock")
DEFAULT_REPORT = Path("artifacts/threat-intel/latest.json")


class AuditError(RuntimeError):
    """The audit could not be completed (bad input or upstream failure)."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit uv.lock dependencies against OSV advisories."
    )
    parser.add_argument("--lockfile", type=Path, default=DEFAULT_LOCKFILE, help="uv.lock to audit")
    parser.add_argument(
        "--report", type=Path, default=DEFAULT_REPORT, help="where to write the JSON report"
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="ID",
        help="accepted-risk advisory id or alias (repeatable)",
    )
    parser.add_argument(
        "--offline",
        type=Path,
        default=None,
        metavar="REPORT",
        help="evaluate a previously written report instead of querying OSV",
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="per-request timeout in seconds"
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    return parser.parse_args(argv)


def parse_lockfile(path: Path) -> list[tuple[str, str]]:
    """Return ``(name, version)`` for every registry package in ``uv.lock``."""
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise AuditError(f"cannot read {path}: {exc}") from exc
    packages: set[tuple[str, str]] = set()
    for package in document.get("package", []):
        name = package.get("name")
        version = package.get("version")
        source = package.get("source") or {}
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        if "registry" not in source:  # skip editable/virtual/local projects
            continue
        packages.add((name, version))
    if not packages:
        raise AuditError(f"{path} contains no registry packages")
    return sorted(packages)


def _severity(vulnerability: dict[str, Any]) -> str:
    """Human severity when the advisory publishes one; ``UNRATED`` otherwise.

    PYSEC entries carry CVSS vectors but no qualitative label. Guessing a band
    from the vector would be wrong, so the raw vectors are kept in the report
    for triage and the summary says ``UNRATED``.
    """
    specific = vulnerability.get("database_specific") or {}
    label = specific.get("severity")
    if isinstance(label, str) and label:
        return label.upper()
    return "UNRATED"


def _cvss(vulnerability: dict[str, Any]) -> list[dict[str, str]]:
    vectors = []
    for entry in vulnerability.get("severity") or []:
        if isinstance(entry, dict) and isinstance(entry.get("score"), str):
            vectors.append(
                {
                    "type": str(entry.get("type") or "UNKNOWN"),
                    "score": entry["score"],
                }
            )
    return vectors


def _fixed_versions(vulnerability: dict[str, Any], package: str) -> list[str]:
    fixed: set[str] = set()
    for affected in vulnerability.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        declared = (affected.get("package") or {}).get("name")
        if str(declared or "").lower() != package.lower():
            continue
        for range_ in affected.get("ranges") or []:
            for event in (range_ or {}).get("events") or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.add(event["fixed"])
    return sorted(fixed)


def _query_batch(client: httpx.Client, packages: list[tuple[str, str]]) -> dict[str, list[str]]:
    """Map advisory id -> affected ``name@version`` entries."""
    affected: dict[str, set[str]] = {}
    for start in range(0, len(packages), BATCH_SIZE):
        chunk = packages[start : start + BATCH_SIZE]
        response = client.post(
            OSV_BATCH_URL,
            json={
                "queries": [
                    {"package": {"name": name, "ecosystem": ECOSYSTEM}, "version": version}
                    for name, version in chunk
                ]
            },
        )
        response.raise_for_status()
        results = (response.json() or {}).get("results") or []
        if len(results) != len(chunk):
            raise AuditError("OSV returned a different number of results than queries")
        for (name, version), result in zip(chunk, results, strict=True):
            for vulnerability in (result or {}).get("vulns") or []:
                advisory_id = vulnerability.get("id")
                if isinstance(advisory_id, str):
                    affected.setdefault(advisory_id, set()).add(f"{name}@{version}")
    return {advisory_id: sorted(entries) for advisory_id, entries in affected.items()}


def fetch_findings(packages: list[tuple[str, str]], *, timeout: float) -> list[dict[str, Any]]:
    """Query OSV for the packages and resolve advisory details."""
    findings: list[dict[str, Any]] = []
    try:
        with httpx.Client(timeout=timeout) as client:
            affected = _query_batch(client, packages)
            for advisory_id in sorted(affected):
                response = client.get(f"{OSV_VULN_URL}{advisory_id}")
                response.raise_for_status()
                vulnerability = response.json() or {}
                for entry in affected[advisory_id]:
                    package, _, version = entry.partition("@")
                    findings.append(
                        {
                            "package": package,
                            "version": version,
                            "id": advisory_id,
                            "aliases": sorted(
                                alias
                                for alias in vulnerability.get("aliases") or []
                                if isinstance(alias, str)
                            ),
                            "summary": str(vulnerability.get("summary") or "").strip(),
                            "severity": _severity(vulnerability),
                            "cvss": _cvss(vulnerability),
                            "fixed_versions": _fixed_versions(vulnerability, package),
                            "url": f"https://osv.dev/vulnerability/{advisory_id}",
                        }
                    )
    except httpx.HTTPError as exc:
        raise AuditError(f"OSV request failed: {type(exc).__name__}: {exc}") from exc
    return sorted(findings, key=lambda finding: (finding["package"], finding["id"]))


def build_report(
    lockfile: Path, packages: list[tuple[str, str]], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    digest = hashlib.sha256(lockfile.read_bytes()).hexdigest()
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "source": {
            "name": "OSV",
            "ecosystem": ECOSYSTEM,
            "batch_url": OSV_BATCH_URL,
        },
        "lockfile": {"path": str(lockfile), "sha256": digest},
        "packages": len(packages),
        "findings": findings,
    }


def evaluate(
    findings: list[dict[str, Any]], ignored: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into blocking and accepted-risk lists."""
    blocking: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    for finding in findings:
        identifiers = {str(finding.get("id") or "")} | {
            str(alias) for alias in finding.get("aliases") or []
        }
        target = accepted if identifiers & ignored else blocking
        target.append(finding)
    return blocking, accepted


def load_report(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuditError(f"cannot read report {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise AuditError(f"{path} is not a threat-intel report")
    return payload


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _print_summary(
    report: dict[str, Any], blocking: list[dict[str, Any]], accepted: list[dict[str, Any]]
) -> None:
    print(
        f"source          : OSV ({ECOSYSTEM})\n"
        f"packages audited: {report.get('packages', '?')}\n"
        f"findings        : {len(blocking) + len(accepted)} "
        f"({len(accepted)} ignored)"
    )
    for finding in blocking:
        fixed = ", ".join(finding.get("fixed_versions") or []) or "no fixed release"
        print(
            f"  {finding.get('severity', 'UNKNOWN'):<8} "
            f"{finding.get('package')} {finding.get('version')}  "
            f"{finding.get('id')}  fixed: {fixed}"
        )
    for finding in accepted:
        print(f"  IGNORED  {finding.get('package')} {finding.get('version')}  {finding.get('id')}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.offline is not None:
            report = load_report(args.offline)
        else:
            packages = parse_lockfile(args.lockfile)
            findings = fetch_findings(packages, timeout=args.timeout)
            report = build_report(args.lockfile, packages, findings)
            write_report(args.report, report)
    except AuditError as exc:
        print(f"threat-intel audit failed: {exc}", file=sys.stderr)
        return 2

    findings = [finding for finding in report["findings"] if isinstance(finding, dict)]
    blocking, accepted = evaluate(findings, set(args.ignore))

    if args.json:
        print(json.dumps({**report, "blocking": blocking, "accepted": accepted}, indent=2))
    else:
        _print_summary(report, blocking, accepted)
        if args.offline is None:
            print(f"report written  : {args.report}")
        if blocking:
            noun = "dependency" if len(blocking) == 1 else "dependencies"
            print(
                f"FAILED: {len(blocking)} unignored {noun} with known vulnerabilities",
                file=sys.stderr,
            )
        else:
            print("OK: no unignored vulnerabilities.")
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
