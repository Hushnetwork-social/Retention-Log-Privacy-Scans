#!/usr/bin/env python3
"""Public-only validation for FEAT-164 retention/log privacy recurring scan packages."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


FORBIDDEN_MARKERS = [
    "rawLogPayload",
    "rawTraceSample",
    "supportCaseContent",
    "supportPayload",
    "voterIdentifier",
    "ballotReference",
    "receiptCapability",
    "privateFinding",
    "privateScannerFinding",
    "restrictedReviewerPayload",
    "privateDependencyRequired",
    "PrivateServer_ElectronicVoting",
    "C:\\",
    "/Users/",
    "/home/",
    '"directRegisterMutation": true',
]


def sha256_hex(path: Path) -> str:
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def validate_json_files(root: Path, errors: list[str]) -> None:
    for path in sorted(root.rglob("*.json")):
        try:
            load_json(path)
        except json.JSONDecodeError as exc:
            errors.append(f"{path}: invalid JSON: {exc}")


def validate_source(root: Path, errors: list[str]) -> None:
    source_path = root / "examples" / "release-baseline" / "retention-log-privacy-recurring-scan-source.json"
    source = load_json(source_path)
    if not isinstance(source, dict):
        errors.append(f"{source_path}: source must be a JSON object")
        return

    scanner = source.get("scannerBaseline")
    if not isinstance(scanner, dict):
        errors.append(f"{source_path}: scannerBaseline is missing")
        return

    catalog_hash = sha256_hex(root / "rules" / "forbidden-material-catalog.json")
    registry_hash = sha256_hex(root / "rules" / "output-family-registry.json")
    if scanner.get("forbiddenMaterialCatalogHash") != catalog_hash:
        errors.append(f"{source_path}: forbidden-material catalog hash mismatch")
    if scanner.get("outputFamilyRegistryHash") != registry_hash:
        errors.append(f"{source_path}: output-family registry hash mismatch")

    readiness = source.get("readinessBaseline", {})
    score = source.get("scorePolicy", {})
    if readiness.get("registerVersionId") != "RDY-REG-v0.1.7":
        errors.append(f"{source_path}: wrong readiness baseline")
    if score.get("dimensionId") != "RDY-DIM-008" or score.get("proposedScoreFrom") != 8 or score.get("proposedScoreTo") != 9:
        errors.append(f"{source_path}: wrong score proposal range")
    if score.get("directRegisterMutation") is not False:
        errors.append(f"{source_path}: direct register mutation must be false")

    public_policy = source.get("publicSafetyPolicy", {})
    if public_policy.get("publicOnlyValidation") is not True:
        errors.append(f"{source_path}: publicOnlyValidation must be true")

    restricted = source.get("restrictedEvidencePolicy", {})
    if restricted.get("payloadPublished") is not False or restricted.get("publicRefFieldsOnly") is not True:
        errors.append(f"{source_path}: restricted evidence must be no-payload public refs only")


def validate_package_manifest(package_root: Path, errors: list[str]) -> None:
    manifest_path = package_root / "retention-log-privacy-recurring-scan-manifest.json"
    if not manifest_path.exists():
        errors.append(f"{manifest_path}: manifest is missing")
        return

    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        errors.append(f"{manifest_path}: manifest must be a JSON object")
        return

    validation_status = manifest.get("validationStatus", {})
    if validation_status.get("status") != "accepted" or validation_status.get("allRequiredGatesAccepted") is not True:
        errors.append(f"{manifest_path}: validation status is not accepted")

    readiness = manifest.get("readinessOutput", {})
    if readiness.get("dimensionId") != "RDY-DIM-008" or readiness.get("proposedScoreFrom") != 8 or readiness.get("proposedScoreTo") != 9:
        errors.append(f"{manifest_path}: readiness output must propose RDY-DIM-008 8 -> 9")
    if readiness.get("directRegisterMutation") is not False:
        errors.append(f"{manifest_path}: direct register mutation must be false")

    restricted = manifest.get("restrictedEvidencePolicy", {})
    if restricted.get("payloadPublished") is not False or restricted.get("publicRefFieldsOnly") is not True:
        errors.append(f"{manifest_path}: restricted evidence policy must be no-payload public refs only")

    for item in manifest.get("artifactHashes", []):
        if not isinstance(item, dict):
            errors.append(f"{manifest_path}: artifact hash entry is not an object")
            continue
        rel_path = item.get("path")
        expected_hash = item.get("sha256Hash")
        if not isinstance(rel_path, str) or not isinstance(expected_hash, str):
            errors.append(f"{manifest_path}: artifact hash entry is missing path or sha256Hash")
            continue
        artifact_path = package_root / rel_path
        if not artifact_path.exists():
            errors.append(f"{manifest_path}: missing artifact {rel_path}")
            continue
        observed_hash = hashlib.sha256(artifact_path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
        if observed_hash != expected_hash:
            errors.append(f"{manifest_path}: hash mismatch for {rel_path}")


def validate_forbidden_markers(root: Path, errors: list[str]) -> None:
    scan_roots = [
        root / "packages",
    ]
    for scan_root in scan_roots:
        if not scan_root.exists():
            continue
        for path in sorted(p for p in scan_root.rglob("*") if p.is_file()):
            if path.name.endswith(".schema-note.md"):
                continue
            text = path.read_text(encoding="utf-8")
            for marker in FORBIDDEN_MARKERS:
                if marker in text:
                    errors.append(f"{path}: forbidden marker {marker}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Retention-Log-Privacy-Scans repository root")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    errors: list[str] = []
    validate_json_files(root, errors)
    validate_source(root, errors)

    packages = sorted((root / "packages" / "retention-log-privacy-recurring-scan").glob("FEAT164-RLP-SCAN-*"))
    for package_root in packages:
        validate_package_manifest(package_root, errors)

    validate_forbidden_markers(root, errors)

    if errors:
        for error in errors:
            print(error)
        return 1

    print("public validation accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
