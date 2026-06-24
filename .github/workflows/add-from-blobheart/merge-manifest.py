#!/usr/bin/env python3
"""Merge one or more new policy manifests into a base manifest with dedup.

Content-addressed deduplication: a SHA-256 hash of all content fields
(model, machine_type, podvm_image_tag, ram_gib, initdata_b64) is computed
per target.  Targets with identical hashes are considered duplicates.

Usage:
    python merge-manifest.py \
        --base attestation-policy/policy-manifest.yaml \
        --new resolved-ref1.yaml resolved-ref2.yaml \
        --output attestation-policy/policy-manifest.yaml
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import yaml

CONTENT_FIELDS = ("model", "machine_type", "podvm_image_tag", "ram_gib", "initdata_b64")


def target_hash(target: dict) -> str:
    """Compute a deterministic content hash for dedup."""
    parts = [str(target.get(f, "")) for f in CONTENT_FIELDS]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def load_manifest(path: Path) -> list[dict]:
    doc = yaml.safe_load(path.read_text()) or {}
    targets = doc.get("targets")
    if targets is None:
        return []
    if not isinstance(targets, list):
        print(f"ERROR: 'targets' in {path} is not a list", file=sys.stderr)
        sys.exit(1)
    return targets


def write_manifest(path: Path, targets: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.dump({"targets": targets}, f, default_flow_style=False, sort_keys=False)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge policy manifests with content-addressed dedup",
    )
    parser.add_argument(
        "--base", required=True, help="Path to the base manifest",
    )
    parser.add_argument(
        "--new", nargs="+", required=True,
        help="Paths to one or more new manifests to merge in",
    )
    parser.add_argument(
        "--output", required=True, help="Output path for the merged manifest",
    )
    args = parser.parse_args()

    base_path = Path(args.base)
    if base_path.exists():
        base_targets = load_manifest(base_path)
    else:
        base_targets = []

    seen: dict[str, dict] = {target_hash(t): t for t in base_targets}

    added = 0
    skipped = 0

    for new_path_str in args.new:
        new_path = Path(new_path_str)
        new_targets = load_manifest(new_path)
        print(f"Processing {new_path} ({len(new_targets)} targets)")

        for target in new_targets:
            h = target_hash(target)
            model = target.get("model", "unknown")
            source = target.get("source", "")

            if h in seen:
                existing = seen[h]
                ex_model = existing.get("model", "?")
                ex_initdata = existing.get("initdata_b64", "")[:12]
                print(f"  {model}: skip, matches existing {ex_model} (initdata {ex_initdata}...)")
                skipped += 1
            else:
                seen[h] = target
                base_targets.append(target)
                added += 1
                print(f"  {model}: added (source: {source})")

    write_manifest(Path(args.output), base_targets)
    print(f"\nMerge complete: {added} added, {skipped} skipped, "
          f"{len(base_targets)} total targets in {args.output}")

    if added == 0:
        sys.exit(0)


if __name__ == "__main__":
    main()
