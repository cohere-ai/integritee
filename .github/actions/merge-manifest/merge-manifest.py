#!/usr/bin/env python3
"""Merge one or more new policy manifests into a base manifest with dedup.

Content-addressed deduplication uses the SHA-384 of file-backed initdata.

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

CONTENT_FIELDS = ("model", "machine_type", "podvm_image_tag", "ram_gib")


def initdata_sha384(target: dict) -> str:
    """Validate and return a file-backed initdata SHA-384 digest."""
    if "initdata_b64" in target:
        raise ValueError("initdata_b64 is not supported")
    digest = target.get("initdata_sha384")
    if (
        not isinstance(digest, str)
        or len(digest) != 96
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("target has invalid initdata_sha384")
    expected_file = f"initdata/{digest}.toml"
    if target.get("initdata_file") != expected_file:
        raise ValueError(f"initdata_file must be {expected_file}")
    return digest


def target_hash(target: dict) -> str:
    """Compute a deterministic content hash for dedup."""
    parts = [str(target.get(f, "")) for f in CONTENT_FIELDS]
    parts.append(initdata_sha384(target))
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

    try:
        seen: dict[str, dict] = {target_hash(t): t for t in base_targets}
    except (ValueError, TypeError) as error:
        print(f"ERROR: invalid base target: {error}", file=sys.stderr)
        sys.exit(1)

    added = 0
    skipped = 0
    added_models: list[str] = []

    for new_path_str in args.new:
        new_path = Path(new_path_str)
        new_targets = load_manifest(new_path)
        print(f"Processing {new_path} ({len(new_targets)} targets)", file=sys.stderr)

        for target in new_targets:
            try:
                h = target_hash(target)
            except (ValueError, TypeError) as error:
                print(f"ERROR: invalid target in {new_path}: {error}", file=sys.stderr)
                sys.exit(1)
            model = target.get("model", "unknown")
            incoming_sources = target.get("sources", [])

            if h in seen:
                existing = seen[h]
                existing_sources = existing.setdefault("sources", [])
                for s in incoming_sources:
                    if s not in existing_sources:
                        existing_sources.append(s)
                ex_model = existing.get("model", "?")
                print(f"  {model}: dedup, sources updated on {ex_model}", file=sys.stderr)
                skipped += 1
            else:
                seen[h] = target
                base_targets.append(target)
                added += 1
                added_models.append(model)
                print(f"  {model}: added (sources={incoming_sources})", file=sys.stderr)

    output_path = Path(args.output)
    write_manifest(output_path, base_targets)
    total = len(base_targets)
    print(f"\nMerge complete: {added} added, {skipped} skipped, "
          f"{total} total targets in {args.output}", file=sys.stderr)

    print(f"added={added}")
    print(f"skipped={skipped}")
    print(f"total={total}")
    print(f"manifest-file={output_path.resolve()}")
    print(f"added-models={','.join(added_models)}")


if __name__ == "__main__":
    main()
