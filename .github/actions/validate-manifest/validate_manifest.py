#!/usr/bin/env python3
"""Validate an Integritee policy manifest."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Any

import yaml

GENERATE_POLICY_ACTION = (
    Path(__file__).resolve().parents[1] / "generate-policy"
)
sys.path.insert(0, str(GENERATE_POLICY_ACTION))

from generate_policy.manifest_contract import (  # noqa: E402
    SCHEMA_VERSION,
    load_machine_types,
    schema_errors,
    schema_version,
    target_content_hash,
    target_provider,
)


def resolve_initdata(target: dict[str, Any], manifest_path: Path) -> str:
    """Verify file-backed initdata is content-addressed and return its SHA-384."""
    if "initdata_b64" in target:
        raise ValueError("initdata_b64 is not supported")
    relative = target["initdata_file"]
    digest = target["initdata_sha384"]
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


def validate_target(
    target: dict[str, Any],
    index: int,
    manifest_path: Path,
    machine_types: dict[str, dict],
) -> tuple[str | None, list[str]]:
    """Validate one manifest target."""
    label = f"target {index}"
    errors: list[str] = []

    try:
        provider = target_provider(target, machine_types, SCHEMA_VERSION)
    except ValueError as error:
        errors.append(f"{label} {error}")
        provider = None

    try:
        resolve_initdata(target, manifest_path)
    except ValueError as error:
        errors.append(f"{label} {error}")
        return None, errors

    if provider is None:
        return None, errors
    normalized = {**target, "provider": provider}
    return target_content_hash(normalized), errors


def validate_schema(document: object) -> list[str]:
    """Return readable JSON Schema errors for a decoded YAML document."""
    try:
        schema_version(document)
    except ValueError as error:
        return [str(error)]
    return schema_errors(document)


def validate_manifest(path: Path) -> list[str]:
    """Return validation errors for a policy manifest."""
    try:
        document = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as error:
        return [f"manifest is not valid YAML: {error}"]

    errors = validate_schema(document)
    if errors:
        return errors
    targets = document["targets"]

    machine_types = load_machine_types()
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
