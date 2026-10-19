#!/usr/bin/env python3
"""Prune targets from the policy manifest by retiring blobheart sources.

For each target, removes retired sources from its `sources` list. If the list
becomes empty, the target is removed from the manifest entirely, along with any
initdata file no longer referenced by a surviving target.

Sources are retired either by naming them (`--retire`) or by keeping only the
newest N (`--keep-latest`), newest meaning closest to the head of blobheart's
main. `--provider` limits either mode to one provider's targets, so a source
shared across providers can be retired on one and kept on the other.

Warns if a provided source is not found in any target's sources list (it may
not have introduced any changes, or was processed as all-duplicate).

Usage:
    python prune.py \
        --manifest attestation-policy/policy-manifest.yaml \
        --retire 47ded742780246155c119caa1b3f90fd8b598c58

    python prune.py \
        --manifest attestation-policy/policy-manifest.yaml \
        --provider gcp --keep-latest 2
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

import yaml

BLOBHEART_REPOSITORY = "cohere-ai/blobheart"
BLOBHEART_DEFAULT_BRANCH = "main"


class PruneResult:
    """Counts and retired sources of one prune.

    A plain class, not a dataclass: this script is loaded by path from other
    workflow scripts and tests, outside sys.modules, where dataclass fails.
    """

    def __init__(
        self,
        *,
        removed: int = 0,
        trimmed: int = 0,
        remaining: int = 0,
        retired: list[str] | None = None,
    ) -> None:
        self.removed = removed
        self.trimmed = trimmed
        self.remaining = remaining
        self.retired = retired or []
        self.warnings: list[str] = []


def prune_initdata(manifest_path: Path, targets: list[dict]) -> None:
    """Delete initdata files the updated manifest no longer references."""
    referenced = {Path(target["initdata_file"]).name for target in targets}
    for path in sorted((manifest_path.parent / "initdata").glob("*.toml")):
        if path.name not in referenced:
            path.unlink()
            print(f"  DELETE initdata: {path.name}", file=sys.stderr)


def in_scope(target: dict, provider: str | None) -> bool:
    return provider is None or target.get("provider") == provider


def scoped_sources(targets: list[dict], provider: str | None) -> list[str]:
    """Sources of the in-scope targets, each once, in manifest order."""
    sources: dict[str, None] = {}
    for target in targets:
        if in_scope(target, provider):
            for source in target.get("sources", []):
                sources.setdefault(source)
    return list(sources)


def commits_behind_main(sha: str) -> int:
    """How many commits blobheart's main is ahead of sha; 0 is the head."""
    result = subprocess.run(
        [
            "gh", "api",
            f"/repos/{BLOBHEART_REPOSITORY}/compare/"
            f"{sha}...{BLOBHEART_DEFAULT_BRANCH}",
            "--jq", "[.status, .ahead_by] | @tsv",
        ],
        check=True,
        text=True,
        capture_output=True,
        timeout=30,
    )
    status, ahead_by = result.stdout.strip().split("\t")
    if status not in {"ahead", "identical"}:
        raise SystemExit(
            f"blobheart source {sha} is not an ancestor of "
            f"{BLOBHEART_DEFAULT_BRANCH} (compare status: {status})"
        )
    return int(ahead_by)


def newest_first(
    sources: Iterable[str],
    distance: Callable[[str], int] = commits_behind_main,
) -> list[str]:
    """Order sources newest first by their distance from main's head.

    Every source was an ancestor of main when it was added, and main only moves
    forward, so the distance is a total order on them. Manifest order is not:
    a deduplicated target collects a newer source after an older target's.
    """
    return sorted(sources, key=distance)


def prune(
    doc: dict,
    retire: set[str],
    provider: str | None = None,
) -> PruneResult:
    """Retire sources from the in-scope targets of doc, in place."""
    targets = doc.get("targets", [])
    result = PruneResult(retired=sorted(retire))

    all_sources = set(scoped_sources(targets, provider))
    for s in sorted(retire - all_sources):
        scope = f"{provider} target" if provider else "target"
        msg = (
            f"source {s} is not mentioned in any {scope} -- "
            "it may not have introduced changes"
        )
        result.warnings.append(msg)
        print(f"WARNING: {msg}", file=sys.stderr)

    remaining_targets: list[dict] = []
    for target in targets:
        if not in_scope(target, provider):
            remaining_targets.append(target)
            continue
        sources = target.get("sources", [])
        new_sources = [s for s in sources if s not in retire]
        model = target.get("model", "unknown")

        if not new_sources:
            print(f"  REMOVE: {model} (sources were: {sources})", file=sys.stderr)
            result.removed += 1
            continue
        if len(new_sources) < len(sources):
            print(f"  TRIM: {model} sources {sources} -> {new_sources}", file=sys.stderr)
            result.trimmed += 1
        target["sources"] = new_sources
        remaining_targets.append(target)

    if not remaining_targets:
        raise SystemExit(
            "refusing to write an empty policy manifest: "
            "at least one target must remain"
        )

    doc["targets"] = remaining_targets
    result.remaining = len(remaining_targets)
    return result


def retire_all_but_latest(
    doc: dict,
    keep: int,
    provider: str | None = None,
    distance: Callable[[str], int] = commits_behind_main,
) -> set[str]:
    """The in-scope sources to retire so that only the newest `keep` remain."""
    if keep < 1:
        raise SystemExit("--keep-latest must be at least 1")
    ordered = newest_first(scoped_sources(doc.get("targets", []), provider), distance)
    kept, retired = ordered[:keep], ordered[keep:]
    scope = f"{provider} " if provider else ""
    print(f"Keeping the newest {keep} {scope}source(s): {kept}", file=sys.stderr)
    if retired:
        print(f"Retiring older {scope}source(s): {retired}", file=sys.stderr)
    return set(retired)


def prune_manifest(
    manifest_path: Path,
    *,
    retire: set[str] | None = None,
    keep_latest: int | None = None,
    provider: str | None = None,
    distance: Callable[[str], int] = commits_behind_main,
) -> PruneResult:
    """Prune the manifest file and its orphaned initdata in place.

    Leaves the files untouched when there is nothing to retire.
    """
    doc = yaml.safe_load(manifest_path.read_text()) or {}
    if keep_latest is not None:
        retire = retire_all_but_latest(doc, keep_latest, provider, distance)
        if not retire:
            remaining = len(doc.get("targets", []))
            return PruneResult(remaining=remaining)
    result = prune(doc, retire or set(), provider)

    with open(manifest_path, "w") as f:
        yaml.dump(doc, f, default_flow_style=False, sort_keys=False)
    prune_initdata(manifest_path, doc["targets"])

    print(f"\nPrune complete: {result.removed} removed, {result.trimmed} trimmed, "
          f"{result.remaining} remaining", file=sys.stderr)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prune retired blobheart sources from policy manifest",
    )
    parser.add_argument(
        "--manifest", required=True, help="Path to the policy manifest",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--retire", nargs="+",
        help="Blobheart SHAs to retire",
    )
    mode.add_argument(
        "--keep-latest", type=int,
        help="Retire all but the newest N blobheart sources",
    )
    parser.add_argument(
        "--provider",
        help="Only prune targets of this provider (e.g. gcp)",
    )
    args = parser.parse_args()

    result = prune_manifest(
        Path(args.manifest),
        retire=set(args.retire) if args.retire else None,
        keep_latest=args.keep_latest,
        provider=args.provider,
    )

    print(f"removed={result.removed}")
    print(f"trimmed={result.trimmed}")
    print(f"remaining={result.remaining}")
    print(f"retired={' '.join(result.retired)}")
    if result.warnings:
        print(f"warnings={'|'.join(result.warnings)}")


if __name__ == "__main__":
    main()
