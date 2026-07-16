#!/usr/bin/env python3
"""Prune targets from the policy manifest by retiring blobheart sources.

For each target, removes retired sources from its `sources` list. If the list
becomes empty, the target is removed from the manifest entirely.

Warns if a provided source is not found in any target's sources list (it may
not have introduced any changes, or was processed as all-duplicate).

Usage:
    python prune.py \
        --manifest attestation-policy/policy-manifest.yaml \
        --retire 47ded742780246155c119caa1b3f90fd8b598c58
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prune retired blobheart sources from policy manifest",
    )
    parser.add_argument(
        "--manifest", required=True, help="Path to the policy manifest",
    )
    parser.add_argument(
        "--retire", nargs="+", required=True,
        help="Blobheart SHAs to retire",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    retire_set = set(args.retire)

    doc = yaml.safe_load(manifest_path.read_text()) or {}
    targets = doc.get("targets", [])

    all_sources = {s for target in targets for s in target.get("sources", [])}

    warnings: list[str] = []
    for s in retire_set - all_sources:
        msg = f"source {s} is not mentioned in any target -- it may not have introduced changes"
        warnings.append(msg)
        print(f"WARNING: {msg}", file=sys.stderr)

    remaining_targets: list[dict] = []
    removed = 0
    trimmed = 0

    for target in targets:
        sources = target.get("sources", [])
        new_sources = [s for s in sources if s not in retire_set]

        if not new_sources:
            model = target.get("model", "unknown")
            print(f"  REMOVE: {model} (sources were: {sources})", file=sys.stderr)
            removed += 1
        else:
            if len(new_sources) < len(sources):
                model = target.get("model", "unknown")
                print(f"  TRIM: {model} sources {sources} -> {new_sources}", file=sys.stderr)
                trimmed += 1
            target["sources"] = new_sources
            remaining_targets.append(target)

    if not remaining_targets:
        raise SystemExit(
            "refusing to write an empty policy manifest: "
            "at least one target must remain"
        )

    doc["targets"] = remaining_targets
    with open(manifest_path, "w") as f:
        yaml.dump(doc, f, default_flow_style=False, sort_keys=False)

    remaining = len(remaining_targets)
    print(f"\nPrune complete: {removed} removed, {trimmed} trimmed, "
          f"{remaining} remaining", file=sys.stderr)

    print(f"removed={removed}")
    print(f"trimmed={trimmed}")
    print(f"remaining={remaining}")
    if warnings:
        print(f"warnings={'|'.join(warnings)}")


if __name__ == "__main__":
    main()
