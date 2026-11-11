#!/usr/bin/env python3
"""Gate a Trivy CVE report against the committed policy in ``trivy.yaml``.

Trivy writes the report; this script decides whether it fails the build. The
split is deliberate: ``trivy.yaml`` is *Bastion's* policy file, not Trivy's
configuration, so every suppression is visible with its image scope, a written
justification and an expiry date. Trivy is invoked with explicit flags and no
``--ignorefile``, so a finding cannot be hidden before this gate sees it.

Policy schema (all keys required, no others accepted)::

    version: 1
    ignore:
      - id: CVE-2024-12345        # Trivy vulnerability id
        images: [llama-cpp]       # image slugs from scripts/image_inventory.py
        statement: "No fixed release; local-only inference."  # why
        expires: 2027-01-31       # the entry stops suppressing after this date

Exit codes: ``0`` no unsuppressed CRITICAL, ``1`` a policy violation or an
unsuppressed CRITICAL, ``2`` the report or policy could not be read.

    uv run python scripts/check_trivy_report.py \
        --report artifacts/compliance/2026-11-11/cve.json --policy trivy.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = ROOT / "trivy.yaml"
POLICY_VERSION = 1
ENTRY_KEYS = {"id", "images", "statement", "expires"}
MIN_STATEMENT = 10


class GateError(RuntimeError):
    """The report or the policy could not be evaluated."""


@dataclass(frozen=True)
class IgnoreEntry:
    vulnerability_id: str
    images: tuple[str, ...]
    statement: str
    expires: date


@dataclass(frozen=True)
class Finding:
    image: str
    vulnerability_id: str
    package: str
    installed: str
    fixed: str


def _parse_date(value: Any, entry_id: str) -> date:
    if not isinstance(value, str):
        raise GateError(f"ignore entry {entry_id}: expires must be a YYYY-MM-DD string")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise GateError(f"ignore entry {entry_id}: invalid expires {value!r}") from exc


def load_policy(path: Path) -> list[IgnoreEntry]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GateError(f"cannot read policy {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise GateError(f"policy {path} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise GateError("policy must be a mapping with 'version' and 'ignore'")
    unknown = set(raw) - {"version", "ignore"}
    if unknown:
        raise GateError(f"policy has unknown keys: {sorted(unknown)}")
    if raw.get("version") != POLICY_VERSION:
        raise GateError(f"policy version must be {POLICY_VERSION}, got {raw.get('version')!r}")
    entries = raw.get("ignore", [])
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise GateError("policy 'ignore' must be a list")

    parsed: list[IgnoreEntry] = []
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise GateError(f"ignore entry #{index} must be a mapping")
        keys = set(entry)
        if keys != ENTRY_KEYS:
            missing = ENTRY_KEYS - keys
            extra = keys - ENTRY_KEYS
            raise GateError(
                f"ignore entry #{index} keys must be {sorted(ENTRY_KEYS)}; "
                f"missing={sorted(missing)} extra={sorted(extra)}"
            )
        vulnerability_id = entry["id"]
        images = entry["images"]
        statement = entry["statement"]
        if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
            raise GateError(f"ignore entry #{index}: id must be a non-empty string")
        if (
            not isinstance(images, list)
            or not images
            or not all(isinstance(item, str) and item.strip() for item in images)
        ):
            raise GateError(f"ignore entry {vulnerability_id}: images must be a non-empty list")
        if not isinstance(statement, str) or len(statement.strip()) < MIN_STATEMENT:
            raise GateError(
                f"ignore entry {vulnerability_id}: statement must be at least "
                f"{MIN_STATEMENT} characters"
            )
        expires = _parse_date(entry["expires"], vulnerability_id)
        for image in images:
            key = (vulnerability_id, image)
            if key in seen:
                raise GateError(f"duplicate ignore entry for {vulnerability_id} on {image}")
            seen.add(key)
        parsed.append(
            IgnoreEntry(
                vulnerability_id=vulnerability_id,
                images=tuple(images),
                statement=statement.strip(),
                expires=expires,
            )
        )
    return parsed


def load_report(path: Path) -> list[Finding]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GateError(f"cannot read report {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise GateError(f"report {path} is not valid JSON: {exc}") from exc

    results = raw.get("Results") if isinstance(raw, dict) else None
    if not isinstance(results, list):
        raise GateError("report has no Results list; is it `trivy image --format json`?")

    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        image = str(result.get("BastionImage") or result.get("Target") or "unknown")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            continue
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            if str(vulnerability.get("Severity", "")).upper() != "CRITICAL":
                continue
            findings.append(
                Finding(
                    image=image,
                    vulnerability_id=str(vulnerability.get("VulnerabilityID", "")),
                    package=str(vulnerability.get("PkgName", "")),
                    installed=str(vulnerability.get("InstalledVersion", "")),
                    fixed=str(vulnerability.get("FixedVersion", "")),
                )
            )
    return findings


def _matches(entry: IgnoreEntry, finding: Finding) -> bool:
    return finding.vulnerability_id == entry.vulnerability_id and any(
        fnmatch(finding.image, pattern) for pattern in entry.images
    )


def evaluate(
    findings: list[Finding], policy: list[IgnoreEntry], today: date
) -> tuple[list[tuple[Finding, IgnoreEntry]], list[Finding], list[IgnoreEntry]]:
    """Return (suppressed, unsuppressed, expired) for one report."""
    expired = [entry for entry in policy if entry.expires < today]
    live = [entry for entry in policy if entry.expires >= today]

    suppressed: list[tuple[Finding, IgnoreEntry]] = []
    unsuppressed: list[Finding] = []
    for finding in findings:
        match = next((entry for entry in live if _matches(entry, finding)), None)
        if match is None:
            unsuppressed.append(finding)
        else:
            suppressed.append((finding, match))
    return suppressed, unsuppressed, expired


def _print_finding(finding: Finding) -> None:
    fixed = finding.fixed or "no fix"
    print(
        f"  CRITICAL {finding.vulnerability_id} "
        f"{finding.package}@{finding.installed} ({fixed}) in {finding.image}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument(
        "--today",
        type=date.fromisoformat,
        default=None,
        help="evaluate against this date (YYYY-MM-DD) instead of the wall clock",
    )
    args = parser.parse_args(argv)
    today = args.today or datetime.now(UTC).date()

    try:
        policy = load_policy(args.policy)
        findings = load_report(args.report)
    except GateError as exc:
        print(f"trivy-gate: {exc}", file=sys.stderr)
        return 2

    suppressed, unsuppressed, expired = evaluate(findings, policy, today)

    print(
        f"trivy-gate: {len(findings)} CRITICAL finding(s), "
        f"{len(suppressed)} suppressed, {len(unsuppressed)} unsuppressed"
    )
    for finding, entry in suppressed:
        print(f"  suppressed {finding.vulnerability_id} in {finding.image}: {entry.statement}")
    if unsuppressed:
        print("trivy-gate: unsuppressed CRITICAL:")
        for finding in unsuppressed:
            _print_finding(finding)
    if expired:
        print("trivy-gate: expired policy entries:")
        for entry in expired:
            print(
                f"  {entry.vulnerability_id} on {', '.join(entry.images)} expired {entry.expires}"
            )

    if unsuppressed or expired:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
