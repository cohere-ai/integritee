#!/usr/bin/env python3
"""Validate an Integritee policy manifest."""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import re
import sys
import zlib
from pathlib import Path
from typing import Any

import yaml

CONTENT_FIELDS = (
    "model",
    "machine_type",
    "podvm_image_tag",
    "ram_gib",
    "initdata_b64",
)
REQUIRED_FIELDS = set(CONTENT_FIELDS) | {"sources"}
SHA_RE = re.compile(r"[0-9a-f]{40}")
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)


def content_hash(target: dict[str, Any]) -> str:
    """Hash the fields that define a policy target."""
    value = "|".join(str(target[field]) for field in CONTENT_FIELDS)
    return hashlib.sha256(value.encode()).hexdigest()


def decode_initdata(value: Any) -> bytes:
    """Decode and decompress a target's initdata."""
    if not isinstance(value, str) or not value:
        raise ValueError("initdata_b64 must be a non-empty string")
    try:
        decoded = base64.b64decode(value, validate=True)
        return gzip.decompress(decoded) if decoded[:2] == b"\x1f\x8b" else decoded
    except (binascii.Error, gzip.BadGzipFile, EOFError, zlib.error) as error:
        raise ValueError(f"invalid initdata_b64: {error}") from error


def validate_target(
    target: Any,
    index: int,
    policy_id: str,
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
        initdata = decode_initdata(target["initdata_b64"])
        if policy_id and policy_id.encode() not in initdata:
            errors.append(f"{label} initdata does not contain policy {policy_id}")
    except ValueError as error:
        errors.append(f"{label} {error}")

    return content_hash(target), errors


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
        target_hash, target_errors = validate_target(target, index, policy_id)
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
