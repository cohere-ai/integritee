#!/usr/bin/env python3
"""Prune targets from the policy manifest by retiring blobheart sources.

For each target, removes retired sources from its `sources` list. If the list
becomes empty, the target is removed from the manifest entirely, along with any
initdata file no longer referenced by a surviving target.

Sources are retired either by naming them (`--retire`) or by keeping only the
newest N (`--keep-latest`), newest meaning closest to the head of blobheart's
main. `--provider` limits either mode to one provider's targets, so a source
shared across providers can be retired on one and kept on the other.

`--protect-deployed ENV...` makes `--keep-latest` deployment-aware: a source an
environment is serving, or was serving one geofence deploy ago, is never
retired, nor is anything newer. When that cannot be established, nothing is
retired: an oversized policy fails its release loudly, while a retired source
that pods still run fails their attestation silently.

Warns if a provided source is not found in any target's sources list (it may
not have introduced any changes, or was processed as all-duplicate).

Usage:
    python prune.py \
        --manifest attestation-policy/policy-manifest.yaml \
        --retire 47ded742780246155c119caa1b3f90fd8b598c58

    python prune.py \
        --manifest attestation-policy/policy-manifest.yaml \
        --provider gcp --keep-latest 3 --protect-deployed production staging
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import yaml

BLOBHEART_REPOSITORY = "cohere-ai/blobheart"
BLOBHEART_DEFAULT_BRANCH = "main"

# The geofence image bakes in k8s/geofence-models (images/geofence/Dockerfile),
# so the commit a geofence deploy shipped decides which CC charts, and so
# which initdata, the environment's models run. Every argocd job in a deploy
# run records a GitHub deployment; only this one ships geofence.
GEOFENCE_DEPLOY_JOB = re.compile(
    r"(^|/ )deploy-blobheart-backend / deploy-backend / deploy$"
)
# The current deploy and the one a rollback would return to.
DEPLOY_HISTORY = 2
# Deployments read per environment while looking for that history.
DEPLOYMENT_SCAN_LIMIT = 100

Api = Callable[[str], Any]


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


def gh_api(path: str) -> Any:
    """GET a GitHub API path with the gh CLI, returning parsed JSON."""
    result = subprocess.run(
        ["gh", "api", path],
        check=True,
        text=True,
        capture_output=True,
        timeout=30,
    )
    return json.loads(result.stdout)


def compare(base: str, head: str, api: Api = gh_api) -> tuple[str, int]:
    """Compare two blobheart refs: (status, commits head is ahead of base)."""
    data = api(f"/repos/{BLOBHEART_REPOSITORY}/compare/{base}...{head}")
    return data["status"], int(data["ahead_by"])


def commits_behind_main(sha: str, api: Api = gh_api) -> int:
    """How many commits blobheart's main is ahead of sha; 0 is the head."""
    status, ahead_by = compare(sha, BLOBHEART_DEFAULT_BRANCH, api)
    if status not in {"ahead", "identical"}:
        raise SystemExit(
            f"blobheart source {sha} is not an ancestor of "
            f"{BLOBHEART_DEFAULT_BRANCH} (compare status: {status})"
        )
    return ahead_by


def cached_distance(api: Api = gh_api) -> Callable[[str], int]:
    """commits_behind_main through api, asking once per source."""
    cache: dict[str, int] = {}

    def distance(sha: str) -> int:
        if sha not in cache:
            cache[sha] = commits_behind_main(sha, api)
        return cache[sha]

    return distance


def newest_first(
    sources: Iterable[str],
    distance: Callable[[str], int],
) -> list[str]:
    """Order sources newest first by their distance from main's head.

    Every source was an ancestor of main when it was added, and main only moves
    forward, so the distance is a total order on them. Manifest order is not:
    a deduplicated target collects a newer source after an older target's.
    """
    return sorted(sources, key=distance)


def recent_geofence_deploys(
    environment: str,
    api: Api = gh_api,
    history: int = DEPLOY_HISTORY,
) -> list[str]:
    """The last `history` distinct blobheart SHAs geofence was deployed at.

    Newest first. A deployment counts once any of its statuses succeeded:
    GitHub marks a superseded non-production deployment inactive, which would
    otherwise hide every staging deploy but the newest.
    """
    deployments = api(
        f"/repos/{BLOBHEART_REPOSITORY}/deployments"
        f"?environment={environment}&per_page={DEPLOYMENT_SCAN_LIMIT}"
    )
    shas: list[str] = []
    for deployment in deployments:
        if deployment["sha"] in shas:
            continue
        statuses = api(
            f"/repos/{BLOBHEART_REPOSITORY}/deployments/"
            f"{deployment['id']}/statuses?per_page=100"
        )
        succeeded = next(
            (s for s in statuses if s.get("state") == "success"), None,
        )
        job = re.search(r"/job/(\d+)$", (succeeded or {}).get("log_url") or "")
        if not job:
            continue
        name = api(
            f"/repos/{BLOBHEART_REPOSITORY}/actions/jobs/{job.group(1)}"
        )["name"]
        if GEOFENCE_DEPLOY_JOB.search(name):
            shas.append(deployment["sha"])
            if len(shas) == history:
                return shas
    raise LookupError(
        f"found {len(shas)} of {history} successful geofence deploys to "
        f"{environment} in its last {DEPLOYMENT_SCAN_LIMIT} deployments"
    )


def serving_source(
    sources: Iterable[str],
    deployed: str,
    api: Api = gh_api,
) -> str | None:
    """The source whose CC charts a blobheart commit ships.

    Sources are the CC-chart commits integritee was told of, so the one serving
    `deployed` is its nearest ancestor among them. None when every source is
    newer: the environment runs charts the manifest no longer holds.
    """
    nearest: tuple[int, str] | None = None
    for source in sources:
        status, ahead_by = compare(source, deployed, api)
        if status in {"ahead", "identical"} and (
            nearest is None or ahead_by < nearest[0]
        ):
            nearest = (ahead_by, source)
    return nearest[1] if nearest else None


def deployed_floor(
    sources: list[str],
    environments: Iterable[str],
    api: Api,
    distance: Callable[[str], int],
) -> int | None:
    """Distance behind main of the oldest source a recent deploy serves.

    Every source at or newer than this is protected: it is running, is a
    rollback target, or is merged and waiting to deploy. None protects
    everything, and is returned whenever the answer cannot be established.
    """
    floor = 0
    try:
        for environment in environments:
            for deployed in recent_geofence_deploys(environment, api):
                source = serving_source(sources, deployed, api)
                if source is None:
                    print(
                        f"::warning::{environment} deploy {deployed[:8]} "
                        "serves CC charts older than every manifest source; "
                        "retiring nothing",
                    )
                    return None
                print(
                    f"{environment} deploy {deployed[:8]} serves source "
                    f"{source[:8]}",
                    file=sys.stderr,
                )
                floor = max(floor, distance(source))
    except (LookupError, KeyError, ValueError, subprocess.SubprocessError) as error:
        print(
            "::warning::could not establish which blobheart sources are "
            f"deployed ({error}); retiring nothing. The token needs "
            "deployments:read and actions:read on blobheart.",
        )
        return None
    return floor


def retire_all_but_latest(
    doc: dict,
    keep: int,
    provider: str | None = None,
    distance: Callable[[str], int] | None = None,
    protect_environments: Iterable[str] = (),
    api: Api = gh_api,
) -> set[str]:
    """The in-scope sources to retire so that only the newest `keep` remain.

    With protect_environments, a source older than the newest `keep` is still
    kept when a recent deploy to one of them serves it or anything older.
    """
    if keep < 1:
        raise SystemExit("--keep-latest must be at least 1")
    if distance is None:
        distance = cached_distance(api)
    ordered = newest_first(scoped_sources(doc.get("targets", []), provider), distance)
    kept, retired = ordered[:keep], ordered[keep:]
    scope = f"{provider} " if provider else ""
    print(f"Keeping the newest {keep} {scope}source(s): {kept}", file=sys.stderr)

    environments = list(protect_environments)
    if retired and environments:
        floor = deployed_floor(ordered, environments, api, distance)
        protected = (
            retired if floor is None
            else [s for s in retired if distance(s) <= floor]
        )
        if protected:
            print(
                f"Keeping {scope}source(s) still deployed to "
                f"{', '.join(environments)}: {protected}",
                file=sys.stderr,
            )
        retired = [s for s in retired if s not in protected]

    if retired:
        print(f"Retiring older {scope}source(s): {retired}", file=sys.stderr)
    return set(retired)


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


def prune_manifest(
    manifest_path: Path,
    *,
    retire: set[str] | None = None,
    keep_latest: int | None = None,
    provider: str | None = None,
    protect_environments: Iterable[str] = (),
    distance: Callable[[str], int] | None = None,
    api: Api = gh_api,
) -> PruneResult:
    """Prune the manifest file and its orphaned initdata in place.

    Leaves the files untouched when there is nothing to retire.
    """
    doc = yaml.safe_load(manifest_path.read_text()) or {}
    if keep_latest is not None:
        retire = retire_all_but_latest(
            doc, keep_latest, provider, distance, protect_environments, api,
        )
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
    parser.add_argument(
        "--protect-deployed", nargs="+", default=[], metavar="ENV",
        help="With --keep-latest, never retire a source these blobheart "
             "environments recently deployed, or anything newer",
    )
    args = parser.parse_args()
    if args.protect_deployed and args.keep_latest is None:
        parser.error("--protect-deployed requires --keep-latest")

    result = prune_manifest(
        Path(args.manifest),
        retire=set(args.retire) if args.retire else None,
        keep_latest=args.keep_latest,
        provider=args.provider,
        protect_environments=args.protect_deployed,
    )

    print(f"removed={result.removed}")
    print(f"trimmed={result.trimmed}")
    print(f"remaining={result.remaining}")
    print(f"retired={' '.join(result.retired)}")
    if result.warnings:
        print(f"warnings={'|'.join(result.warnings)}")


if __name__ == "__main__":
    main()
