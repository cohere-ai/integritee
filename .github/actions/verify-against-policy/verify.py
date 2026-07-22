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

RELEASE_WORKFLOW_URL = (
    "https://github.com/cohere-ai/integritee/actions/workflows/release-policy.yaml"
)


def gh(*args: str, token: str | None = None) -> str:
    env = None
    if token:
        env = {**os.environ, "GH_TOKEN": token}
    result = subprocess.run(
        ["gh", *args],
        capture_output=True, text=True, env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def run_script(script: Path, args: list[str], *,
               env: dict[str, str] | None = None) -> dict[str, str]:
    """Run a sibling Python script, returning its stdout key=value pairs."""
    result = subprocess.run(
        ["python3", str(script), *args],
        capture_output=True, text=True, env=env,
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


def derive_manifests(derive_script: Path, runner_temp: Path,
                     blobheart_refs: str | None, blobheart_dir: str | None,
                     token: str) -> list[str]:
    """Call derive.py for each ref or a local dir, returning manifest file paths."""
    env = {**os.environ, "GH_TOKEN": token}
    manifest_files = []

    if blobheart_dir:
        out = runner_temp / "derived-manifest-local.yaml"
        run_script(derive_script, ["--blobheart-dir", blobheart_dir, "--output", str(out)],
                   env=env)
        manifest_files.append(str(out))
    elif blobheart_refs:
        for ref in blobheart_refs.split():
            print(f"Deriving manifest from blobheart ref: {ref}", file=sys.stderr)
            out = runner_temp / f"derived-manifest-{ref}.yaml"
            run_script(derive_script, ["--blobheart-ref", ref, "--output", str(out)],
                       env=env)
            manifest_files.append(str(out))
    else:
        print("ERROR: one of BLOBHEART_REFS or BLOBHEART_DIR must be set", file=sys.stderr)
        sys.exit(1)

    return manifest_files


def fetch_release_manifest(runner_temp: Path, token: str) -> tuple[Path, str]:
    """Fetch policy manifest from the latest integritee release.

    Returns (manifest_path, release_tag). Raises RuntimeError on failure.
    """
    release_tag = gh(
        "release", "view",
        "--repo", "cohere-ai/integritee",
        "--json", "tagName", "-q", ".tagName",
        token=token,
    )
    if not release_tag:
        raise RuntimeError("No releases found on cohere-ai/integritee")

    print(f"Latest release: {release_tag}", file=sys.stderr)

    download_dir = runner_temp / "integritee-release"
    download_dir.mkdir(parents=True, exist_ok=True)
    gh(
        "release", "download", release_tag,
        "--repo", "cohere-ai/integritee",
        "--pattern", "policy-manifest.yaml",
        "--dir", str(download_dir),
        "--clobber",
        token=token,
    )
    manifest_path = download_dir / "policy-manifest.yaml"
    if not manifest_path.is_file():
        raise RuntimeError(f"Release {release_tag} does not contain policy-manifest.yaml")

    return manifest_path, release_tag


def coverage_failure_message(
    release_tag: str,
    added: int,
    added_models: str,
    *,
    local_manifest: bool,
) -> str:
    """Build an actionable policy coverage failure message."""
    coverage = (
        f"{added} target(s) are not covered by {release_tag}: {added_models}"
    )
    if local_manifest:
        return f"ERROR: Local policy verification failed. {coverage}"
    return (
        f"ERROR: Latest Integritee policy release is not ready. {coverage}\n"
        "A policy release may still be running for this Blobheart commit.\n"
        f"Check {RELEASE_WORKFLOW_URL} and rerun the deployment after "
        "the Release Policy workflow succeeds."
    )


def main() -> None:
    blobheart_refs = os.environ.get("BLOBHEART_REFS") or None
    blobheart_dir = os.environ.get("BLOBHEART_DIR") or None
    blobheart_token = os.environ["BLOBHEART_TOKEN"]
    integritee_token = os.environ.get("INTEGRITEE_TOKEN") or None
    local_manifest = os.environ.get("POLICY_MANIFEST") or None
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
        if max_attempts > 1:
            print(f"=== Attempt {attempt}/{max_attempts} ===", file=sys.stderr)

        if local_manifest:
            manifest_path = Path(local_manifest)
            release_tag = "local"
            print(f"Using local manifest: {manifest_path}", file=sys.stderr)
        else:
            manifest_path, release_tag = fetch_release_manifest(runner_temp, integritee_token)

        merge_output = run_script(merge_script, [
            "--base", str(manifest_path),
            "--new", *manifest_files,
            "--output", str(runner_temp / "merged-verify.yaml"),
        ])

        added = int(merge_output.get("added", "0"))
        added_models = merge_output.get("added-models", "")

        if added == 0:
            print(f"All targets are covered by {release_tag}", file=sys.stderr)
            print(f"release-tag={release_tag}")
            sys.exit(0)

        if attempt < max_attempts:
            print(
                f"{added} target(s) not covered by "
                f"{release_tag}: {added_models}",
                file=sys.stderr,
            )
            print(f"Retrying in {retry_delay}s...", file=sys.stderr)
            time.sleep(retry_delay)

    print(f"release-tag={release_tag}")
    print(
        coverage_failure_message(
            release_tag,
            added,
            added_models,
            local_manifest=bool(local_manifest),
        ),
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
