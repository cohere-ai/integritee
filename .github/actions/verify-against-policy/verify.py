#!/usr/bin/env python3
"""Verify that the latest integritee release covers all derived targets.

Fetches the release manifest via GitHub CLI, runs merge-manifest to check
for uncovered targets, and retries if configured.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path


def gh(*args: str) -> str:
    result = subprocess.run(
        ["gh", *args],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def get_latest_release_tag() -> str | None:
    try:
        return gh(
            "release", "view",
            "--repo", "cohere-ai/integritee",
            "--json", "tagName", "-q", ".tagName",
        )
    except RuntimeError:
        return None


def download_release_manifest(tag: str, dest: Path) -> None:
    content = gh(
        "api",
        f"repos/cohere-ai/integritee/contents/attestation-policy/policy-manifest.yaml?ref={tag}",
        "-H", "Accept: application/vnd.github.v3.raw",
    )
    dest.write_text(content)


def run_merge(merge_script: Path, base: Path, new_files: list[str], output: Path) -> dict[str, str]:
    result = subprocess.run(
        ["python3", str(merge_script), "--base", str(base), "--new", *new_files, "--output", str(output)],
        capture_output=True, text=True,
    )
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    if result.returncode != 0:
        raise RuntimeError(f"merge-manifest.py failed: {result.stderr}")

    outputs = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            outputs[key] = value
    return outputs


def main() -> None:
    manifest_files = os.environ["MANIFEST_FILES"].split()
    retries = int(os.environ.get("RETRIES", "0"))
    retry_delay = int(os.environ.get("RETRY_DELAY", "30"))
    runner_temp = Path(os.environ.get("RUNNER_TEMP", "/tmp"))

    action_path = Path(os.environ.get("ACTION_PATH", Path(__file__).parent))
    merge_script = action_path / ".." / "merge-manifest" / "merge-manifest.py"

    max_attempts = retries + 1
    release_tag = ""

    for attempt in range(1, max_attempts + 1):
        print(f"=== Attempt {attempt}/{max_attempts} ===", file=sys.stderr)

        release_tag = get_latest_release_tag()
        if not release_tag:
            print("No releases found on cohere-ai/integritee", file=sys.stderr)
            if attempt < max_attempts:
                print(f"Retrying in {retry_delay}s...", file=sys.stderr)
                time.sleep(retry_delay)
                continue
            print(f"release-tag=")
            print(f"ERROR: No releases found after {max_attempts} attempt(s)", file=sys.stderr)
            sys.exit(1)

        print(f"Latest release: {release_tag}", file=sys.stderr)

        release_manifest = runner_temp / "release-manifest.yaml"
        download_release_manifest(release_tag, release_manifest)

        merge_output = run_merge(
            merge_script,
            base=release_manifest,
            new_files=manifest_files,
            output=runner_temp / "merged-verify.yaml",
        )

        added = int(merge_output.get("added", "0"))
        added_models = merge_output.get("added-models", "")

        if added == 0:
            print(f"All targets are covered by release {release_tag}", file=sys.stderr)
            print(f"release-tag={release_tag}")
            sys.exit(0)

        print(f"{added} target(s) not covered by release {release_tag}: {added_models}", file=sys.stderr)
        if attempt < max_attempts:
            print(f"Retrying in {retry_delay}s...", file=sys.stderr)
            time.sleep(retry_delay)

    print(f"release-tag={release_tag}")
    print(f"ERROR: Verification failed after {max_attempts} attempt(s)", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
