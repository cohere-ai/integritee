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
    "ram_gib",
)
REQUIRED_FIELDS = set(CONTENT_FIELDS) | {
    "initdata_file",
    "initdata_sha384",
    "sources",
}
SHA_RE = re.compile(r"[0-9a-f]{40}")
SHA384_RE = re.compile(r"[0-9a-f]{96}")
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)


def content_hash(target: dict[str, Any], initdata_sha384: str) -> str:
    """Hash the fields that define a policy target."""
    values = [str(target[field]) for field in CONTENT_FIELDS]
    values.append(initdata_sha384)
    value = "|".join(values)
    return hashlib.sha256(value.encode()).hexdigest()


def resolve_initdata(target: dict[str, Any], manifest_path: Path) -> tuple[bytes, str]:
    """Load file-backed initdata and return its bytes and SHA-384."""
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
    value = initdata_path.read_bytes()
    actual_digest = hashlib.sha384(value).hexdigest()
    if actual_digest != digest:
        raise ValueError(
            f"initdata_sha384 mismatch: expected {digest}, got {actual_digest}"
        )
    return value, digest


def validate_target(
    target: Any,
    index: int,
    policy_id: str,
    manifest_path: Path,
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
    if not isinstance(target["ram_gib"], int) or target["ram_gib"] <= 0:
        errors.append(f"{label} has invalid ram_gib")

    sources = target["sources"]
    if not isinstance(sources, list) or not sources:
        errors.append(f"{label} sources must be a non-empty list")
    else:
        for source in sources:
            if not isinstance(source, str) or not SHA_RE.fullmatch(source):
                errors.append(f"{label} has invalid source ref: {source}")

    try:
        initdata, initdata_digest = resolve_initdata(target, manifest_path)
        if policy_id and policy_id.encode() not in initdata:
            errors.append(f"{label} initdata does not contain policy {policy_id}")
    except ValueError as error:
        errors.append(f"{label} {error}")
        return None, errors

    return content_hash(target, initdata_digest), errors


def validate_manifest(path: Path, policy_id: str = "") -> list[str]:
    """Return validation errors for a policy manifest."""
    if policy_id and not UUID_RE.fullmatch(policy_id):
        return [f"invalid ITA policy ID: {policy_id}"]

    document = yaml.safe_load(path.read_text()) or {}
    if not isinstance(document, dict):
        return ["policy manifest must be a mapping"]
    targets = document.get("targets")
    if not isinstance(targets, list) or not targets:
        return ["policy manifest must contain a non-empty targets list"]

    errors: list[str] = []
    hashes: set[str] = set()
    for index, target in enumerate(targets):
        target_hash, target_errors = validate_target(
            target,
            index,
            policy_id,
            path,
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
    parser.add_argument("--policy-id", default="")
    args = parser.parse_args()

    errors = validate_manifest(args.manifest, args.policy_id)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        raise SystemExit(1)

    targets = yaml.safe_load(args.manifest.read_text())["targets"]
    print(f"Validated {len(targets)} policy targets")


if __name__ == "__main__":
    main()
