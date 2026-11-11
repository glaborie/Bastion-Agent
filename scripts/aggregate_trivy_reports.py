#!/usr/bin/env python3
"""Merge per-image Trivy reports into one SBOM, one CVE report and a manifest.

``scripts/trivy-scan.sh`` scans each tarball separately, because ``trivy image
--input`` accepts one archive at a time. This script produces the two artifacts
the gate and a reviewer expect:

* ``sbom.cdx.json`` — one CycloneDX document whose ``components`` and
  ``vulnerabilities`` are the union of every image's document (de-duplicated by
  ``bom-ref``/finding id), with a synthetic ``bastion-agent-image-set`` root.
* ``cve.json`` — one Trivy JSON document whose ``Results`` keep every image's
  results, each tagged with ``BastionImage`` so the policy gate can scope a
  suppression to one image.
* ``manifest.json`` — the image references that were scanned, their slugs and
  the file each report came from, so the set is auditable on its own.

    uv run python scripts/aggregate_trivy_reports.py \
        --raw artifacts/compliance/work/raw --out artifacts/compliance/2026-11-11
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


class AggregateError(RuntimeError):
    """The per-image reports could not be merged."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AggregateError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AggregateError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise AggregateError(f"{path} must contain a JSON object")
    return raw


def _component_key(component: dict[str, Any]) -> str:
    ref = component.get("bom-ref")
    if isinstance(ref, str) and ref:
        return ref
    return f"{component.get('name', '')}@{component.get('version', '')}"


def merge_cyclonedx(documents: list[dict[str, Any]]) -> dict[str, Any]:
    components: dict[str, dict[str, Any]] = {}
    vulnerabilities: dict[str, dict[str, Any]] = {}
    spec_version = "1.5"
    for document in documents:
        spec_version = str(document.get("specVersion") or spec_version)
        for component in document.get("components") or []:
            if isinstance(component, dict):
                components.setdefault(_component_key(component), component)
        for vulnerability in document.get("vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            affects = vulnerability.get("affects") or []
            target = ""
            if isinstance(affects, list) and affects and isinstance(affects[0], dict):
                target = str(affects[0].get("ref", ""))
            key = f"{vulnerability.get('id', '')}:{target}"
            vulnerabilities.setdefault(key, vulnerability)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "component": {
                "type": "application",
                "name": "bastion-agent-image-set",
                "description": "Union of every container image the compose stack ships",
            },
        },
        "components": sorted(components.values(), key=_component_key),
        "vulnerabilities": sorted(vulnerabilities.values(), key=lambda item: str(item.get("id"))),
    }


def merge_trivy_results(
    documents: list[dict[str, Any]], report_files: list[Path]
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for document, report_file in zip(documents, report_files, strict=True):
        image_slug = report_file.name.removesuffix(".json")
        for result in document.get("Results") or []:
            if not isinstance(result, dict):
                continue
            merged = dict(result)
            target = str(merged.get("Target", ""))
            merged["Target"] = f"{image_slug}:{target}" if target else image_slug
            merged["BastionImage"] = image_slug
            results.append(merged)
    return {
        "SchemaVersion": 2,
        "ArtifactName": "bastion-agent-image-set",
        "ArtifactType": "container_image",
        "Results": results,
    }


def aggregate(raw_dir: Path, out_dir: Path, images: list[str]) -> dict[str, Any]:
    try:
        sbom_files = sorted(raw_dir.glob("*.cdx.json"))
        report_files = sorted(
            path for path in raw_dir.glob("*.json") if not path.name.endswith(".cdx.json")
        )
    except OSError as exc:
        raise AggregateError(f"cannot list {raw_dir}: {exc}") from exc

    if not sbom_files or not report_files:
        raise AggregateError(f"no reports in {raw_dir}; run scripts/scan_images.sh first")
    if len(sbom_files) != len(report_files):
        raise AggregateError(
            f"{len(sbom_files)} SBOM(s) and {len(report_files)} CVE report(s) in {raw_dir}"
        )

    sbom_documents = [_read_json(path) for path in sbom_files]
    report_documents = [_read_json(path) for path in report_files]
    sbom = merge_cyclonedx(sbom_documents)
    cve = merge_trivy_results(report_documents, report_files)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "sbom.cdx.json").write_text(
        json.dumps(sbom, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    (out_dir / "cve.json").write_text(
        json.dumps(cve, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )

    manifest = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "images": [{"reference": image} for image in images],
        "sbom": "sbom.cdx.json",
        "cve_report": "cve.json",
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "images",
        nargs="+",
        metavar="IMAGE",
        help="image references in the same order the scanner wrote them",
    )
    args = parser.parse_args(argv)

    try:
        manifest = aggregate(args.raw, args.out, args.images)
    except AggregateError as exc:
        print(f"aggregate: {exc}", file=sys.stderr)
        return 2

    print(f"aggregate: {len(manifest['images'])} image(s) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
