#!/usr/bin/env python3
"""Verify that the latest integritee release covers all derived targets.

Derives manifests from blobheart, fetches the release manifest via GitHub CLI,
runs merge-manifest to check for uncovered targets, and retries if configured.
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


def run_script(script: Path, args: list[str]) -> dict[str, str]:
    """Run a sibling Python script, returning its stdout key=value pairs."""
    result = subprocess.run(
        ["python3", str(script), *args],
        capture_output=True, text=True,
    )
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    if result.returncode != 0:
        raise RuntimeError(f"{script.name} failed (exit {result.returncode})")

    outputs = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            outputs[key] = value
    return outputs


def run_derive(derive_script: Path, args: list[str], token: str) -> None:
    """Run derive.py with the blobheart token, redirecting all output to stderr."""
    env = {**os.environ, "GH_TOKEN": token}
    result = subprocess.run(
        ["python3", str(derive_script), *args],
        capture_output=True, text=True, env=env,
    )
    if result.stdout:
        print(result.stdout, file=sys.stderr, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    if result.returncode != 0:
        raise RuntimeError(f"derive.py failed (exit {result.returncode})")


def derive_manifests(derive_script: Path, runner_temp: Path,
                     blobheart_refs: str | None, blobheart_dir: str | None,
                     token: str) -> list[str]:
    """Call derive.py for each ref or a local dir, returning manifest file paths."""
    manifest_files = []

    if blobheart_dir:
        out = runner_temp / "derived-manifest-local.yaml"
        run_derive(derive_script, ["--blobheart-dir", blobheart_dir, "--output", str(out)], token)
        manifest_files.append(str(out))
    elif blobheart_refs:
        for ref in blobheart_refs.split():
            print(f"Deriving manifest from blobheart ref: {ref}", file=sys.stderr)
            out = runner_temp / f"derived-manifest-{ref}.yaml"
            run_derive(derive_script, ["--blobheart-ref", ref, "--output", str(out)], token)
            manifest_files.append(str(out))
    else:
        print("ERROR: one of BLOBHEART_REFS or BLOBHEART_DIR must be set", file=sys.stderr)
        sys.exit(1)

    return manifest_files


def main() -> None:
    blobheart_refs = os.environ.get("BLOBHEART_REFS") or None
    blobheart_dir = os.environ.get("BLOBHEART_DIR") or None
    blobheart_token = os.environ["BLOBHEART_TOKEN"]
    retries = int(os.environ.get("RETRIES", "0"))
    retry_delay = int(os.environ.get("RETRY_DELAY", "30"))
    runner_temp = Path(os.environ.get("RUNNER_TEMP", "/tmp"))

    action_path = Path(os.environ.get("ACTION_PATH", str(Path(__file__).parent)))
    derive_script = action_path / ".." / "derive-manifest" / "derive.py"
    merge_script = action_path / ".." / "merge-manifest" / "merge-manifest.py"

    print("Deriving manifests from blobheart...", file=sys.stderr)
    manifest_files = derive_manifests(derive_script, runner_temp, blobheart_refs, blobheart_dir, blobheart_token)

    max_attempts = retries + 1
    release_tag = ""

    for attempt in range(1, max_attempts + 1):
        print(f"=== Attempt {attempt}/{max_attempts} ===", file=sys.stderr)

        try:
            release_tag = gh(
                "release", "view",
                "--repo", "cohere-ai/integritee",
                "--json", "tagName", "-q", ".tagName",
            )
        except RuntimeError:
            release_tag = ""

        if not release_tag:
            print("No releases found on cohere-ai/integritee", file=sys.stderr)
            if attempt < max_attempts:
                print(f"Retrying in {retry_delay}s...", file=sys.stderr)
                time.sleep(retry_delay)
                continue
            print("release-tag=")
            print(f"ERROR: No releases found after {max_attempts} attempt(s)", file=sys.stderr)
            sys.exit(1)

        print(f"Latest release: {release_tag}", file=sys.stderr)

        release_manifest = runner_temp / "release-manifest.yaml"
        content = gh(
            "api",
            f"repos/cohere-ai/integritee/contents/attestation-policy/policy-manifest.yaml?ref={release_tag}",
            "-H", "Accept: application/vnd.github.v3.raw",
        )
        release_manifest.write_text(content)

        merge_output = run_script(merge_script, [
            "--base", str(release_manifest),
            "--new", *manifest_files,
            "--output", str(runner_temp / "merged-verify.yaml"),
        ])

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
