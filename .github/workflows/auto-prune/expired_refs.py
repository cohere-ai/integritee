#!/usr/bin/env python3
"""Print the Blobheart refs in the policy manifest that are due for retirement.

A ref is retired a grace period after the next ref merges into Blobheart, so
the newer ref has time to deploy and roll out. The newest ref is never retired.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

BLOBHEART_REPOSITORY = "cohere-ai/blobheart"
SHA_RE = re.compile(r"[0-9a-f]{40}")


def merged_at(ref: str) -> datetime:
    """Return when a Blobheart commit landed on main.

    Blobheart squash-merges through GitHub, so the committer date is the merge
    time.
    """
    if not SHA_RE.fullmatch(ref):
        raise SystemExit(f"invalid Blobheart commit SHA in manifest: {ref}")
    date = subprocess.run(
        [
            "gh", "api", f"/repos/{BLOBHEART_REPOSITORY}/commits/{ref}",
            "--jq", ".commit.committer.date",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    return datetime.fromisoformat(date)


def refs_to_retire(
    merged: dict[str, datetime],
    now: datetime,
    grace: timedelta,
) -> list[str]:
    """Retire each ref once the next ref has been merged for `grace` duration."""
    ordered = sorted(merged, key=merged.get)
    retire = []
    for older, newer in zip(ordered, ordered[1:]):
        if now - merged[newer] >= grace:
            retire.append(older)
    return retire


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--days", type=int, required=True)
    args = parser.parse_args()

    doc = yaml.safe_load(args.manifest.read_text()) or {}
    sources = {s for t in doc.get("targets", []) for s in t.get("sources", [])}
    merged = {ref: merged_at(ref) for ref in sources}
    print(" ".join(refs_to_retire(
        merged, datetime.now(timezone.utc), timedelta(days=args.days),
    )))


if __name__ == "__main__":
    main()
