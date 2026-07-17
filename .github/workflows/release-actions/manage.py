#!/usr/bin/env python3
"""Resolve the next Integritee Actions release tag."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterable
from pathlib import Path

TAG_RE = re.compile(r"actions-v(\d+)\.(\d+)\.(\d+)")


def resolve_version(tags: Iterable[str], sha_tags: Iterable[str]) -> tuple[str, bool]:
    """Return the release tag and whether it needs to be created."""
    versions = {
        tuple(map(int, match.groups())): tag
        for tag in tags
        if (match := TAG_RE.fullmatch(tag))
    }
    current_tags = set(sha_tags)
    existing = [
        (version, tag)
        for version, tag in versions.items()
        if tag in current_tags
    ]
    if existing:
        return max(existing)[1], False

    if not versions:
        return "actions-v1.0.0", True

    major, minor, patch = max(versions)
    return f"actions-v{major}.{minor}.{patch + 1}", True


def git_tags(*args: str) -> list[str]:
    """List tags selected by git."""
    result = subprocess.run(
        ["git", "tag", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.splitlines()


def main() -> None:
    """Write the resolved release information to GITHUB_OUTPUT."""
    version, create = resolve_version(
        git_tags("--list", "actions-v*"),
        git_tags("--points-at", os.environ["GITHUB_SHA"], "--list", "actions-v*"),
    )
    output = Path(os.environ["GITHUB_OUTPUT"])
    with output.open("a") as stream:
        stream.write(f"version={version}\n")
        stream.write(f"create={str(create).lower()}\n")


if __name__ == "__main__":
    main()
