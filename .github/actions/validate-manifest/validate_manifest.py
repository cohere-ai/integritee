#!/usr/bin/env python3
"""Validate an Integritee policy manifest."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path
from typing import Any

import yaml

CONTENT_FIELDS = (
    "model",
    "machine_type",
    "podvm_image_tag",
)
REQUIRED_FIELDS = set(CONTENT_FIELDS) | {
    "initdata_file",
    "initdata_sha384",
    "sources",
}
SHA_RE = re.compile(r"[0-9a-f]{40}")
SHA384_RE = re.compile(r"[0-9a-f]{96}")

# Shared with derive.py and the generator; see the header of the table itself.
MACHINE_TYPES_PATH = (
    Path(__file__).resolve().parents[1]
    / "generate-policy/generate_policy/machine-types.yaml"
)


def content_hash(target: dict[str, Any], initdata_sha384: str) -> str:
    """Hash the fields that define a policy target."""
    values = [str(target[field]) for field in CONTENT_FIELDS]
    values.append(initdata_sha384)
    value = "|".join(values)
    return hashlib.sha256(value.encode()).hexdigest()


def resolve_initdata(target: dict[str, Any], manifest_path: Path) -> str:
    """Verify file-backed initdata is content-addressed and return its SHA-384."""
    if "initdata_b64" in target:
        raise ValueError("initdata_b64 is not supported")
    relative = target["initdata_file"]
    digest = target["initdata_sha384"]
    if not isinstance(digest, str) or not SHA384_RE.fullmatch(digest):
        raise ValueError("initdata_sha384 must be 96 lowercase hex characters")
    expected_relative = f"initdata/{digest}.toml"
    if relative != expected_relative:
        raise ValueError(f"initdata_file must be {expected_relative}")

    initdata_path = manifest_path.parent / expected_relative
    if not initdata_path.is_file():
        raise ValueError(f"initdata file does not exist: {relative}")
    actual_digest = hashlib.sha384(initdata_path.read_bytes()).hexdigest()
    if actual_digest != digest:
        raise ValueError(
            f"initdata_sha384 mismatch: expected {digest}, got {actual_digest}"
        )
    return digest


def load_machine_types() -> dict[str, dict]:
    """Load the shared machine type table."""
    return yaml.safe_load(MACHINE_TYPES_PATH.read_text()) or {}


def validate_target(
    target: Any,
    index: int,
    manifest_path: Path,
    machine_types: dict[str, dict],
) -> tuple[str | None, list[str]]:
    """Validate one manifest target."""
    label = f"target {index}"
    if not isinstance(target, dict):
        return None, [f"{label} must be a mapping"]

    errors: list[str] = []
    missing = REQUIRED_FIELDS - set(target)
    if missing:
        return None, [f"{label} missing fields: {sorted(missing)}"]

    for field in ("model", "machine_type", "podvm_image_tag"):
        if not isinstance(target[field], str) or not target[field]:
            errors.append(f"{label} has invalid {field}")
    if target["machine_type"] not in machine_types:
        errors.append(
            f"{label} has unknown machine type "
            f"'{target['machine_type']}' -- update machine-types.yaml"
        )

    sources = target["sources"]
    if not isinstance(sources, list) or not sources:
        errors.append(f"{label} sources must be a non-empty list")
    else:
        for source in sources:
            if not isinstance(source, str) or not SHA_RE.fullmatch(source):
                errors.append(f"{label} has invalid source ref: {source}")

    try:
        initdata_digest = resolve_initdata(target, manifest_path)
    except ValueError as error:
        errors.append(f"{label} {error}")
        return None, errors

    return content_hash(target, initdata_digest), errors


def validate_manifest(path: Path) -> list[str]:
    """Return validation errors for a policy manifest."""
    document = yaml.safe_load(path.read_text()) or {}
    if not isinstance(document, dict):
        return ["policy manifest must be a mapping"]
    targets = document.get("targets")
    if not isinstance(targets, list) or not targets:
        return ["policy manifest must contain a non-empty targets list"]

    machine_types = load_machine_types()
    errors: list[str] = []
    hashes: set[str] = set()
    for index, target in enumerate(targets):
        target_hash, target_errors = validate_target(
            target, index, path, machine_types
        )
        errors.extend(target_errors)
        if target_hash is not None:
            if target_hash in hashes:
                errors.append(f"target {index} duplicates another target")
            hashes.add(target_hash)
    return errors


def main() -> None:
    """Validate a policy manifest from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()

    errors = validate_manifest(args.manifest)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        raise SystemExit(1)

    targets = yaml.safe_load(args.manifest.read_text())["targets"]
    print(f"Validated {len(targets)} policy targets")


if __name__ == "__main__":
    main()
