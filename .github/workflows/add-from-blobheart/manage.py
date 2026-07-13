#!/usr/bin/env python3
"""Manage Blobheart policy manifest updates and releases."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
SHA_RE = re.compile(r"[0-9a-f]{40}")


def run(
    *command: str,
    check: bool = True,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a command without invoking a shell."""
    return subprocess.run(
        command,
        check=check,
        text=True,
        capture_output=capture_output,
    )


def validate_repository(repository: str) -> None:
    """Validate an OWNER/NAME repository identifier."""
    if not REPOSITORY_RE.fullmatch(repository):
        raise SystemExit("repository must be OWNER/NAME")


def validate(args: argparse.Namespace) -> None:
    """Validate workflow inputs before deriving manifests."""
    refs = args.blobheart_refs.split()
    if not refs:
        raise SystemExit("at least one Blobheart commit SHA is required")
    invalid = [ref for ref in refs if not SHA_RE.fullmatch(ref)]
    if invalid:
        raise SystemExit(f"invalid Blobheart commit SHA: {invalid[0]}")


def update(args: argparse.Namespace) -> None:
    """Install the merged manifest and report changes."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        raise SystemExit("GITHUB_OUTPUT is required")
    shutil.copyfile(args.merged, args.manifest)

    status = run(
        "git",
        "diff",
        "--quiet",
        "--",
        str(args.manifest),
        check=False,
    ).returncode
    if status not in {0, 1}:
        raise SystemExit("failed to compare the merged policy manifest")
    changed = status == 1
    with Path(output_path).open("a") as output:
        output.write(f"changed={str(changed).lower()}\n")
    if not changed:
        print("No changes to manifest; all targets already track this ref")
        return

    changed_files = run(
        "git",
        "diff",
        "--name-only",
        capture_output=True,
    ).stdout.splitlines()
    if changed_files != [str(args.manifest)]:
        raise SystemExit(f"unexpected changed files: {changed_files}")

    print(
        f"Manifest updated: {args.added} new targets; "
        "sources updated on deduplicated targets"
    )
    run("git", "diff", "--", str(args.manifest))


def publish_pr(args: argparse.Namespace) -> None:
    """Create and merge the generated manifest PR."""
    refs = args.blobheart_refs.split()
    if not refs or any(not SHA_RE.fullmatch(ref) for ref in refs):
        raise SystemExit("blobheart refs must be 40-character lowercase SHAs")
    validate_repository(args.repository)

    run_id = os.environ.get("GITHUB_RUN_ID", "")
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not run_id.isdigit():
        raise SystemExit("GITHUB_RUN_ID must be numeric")
    if not output_path:
        raise SystemExit("GITHUB_OUTPUT is required")

    short_ref = refs[0][:12]
    branch = f"automation/blobheart-policy-{short_ref}-{run_id}"
    body = f"""## Summary
- derive confidential-computing targets from Blobheart commit(s) `{args.blobheart_refs}`
- update the generated production policy manifest

## Validation
- source refs are pinned 40-character commit SHAs
- target content is deduplicated by model, machine type, PodVM image, RAM, and initdata

Automated manifest update; no hand-authored policy code.
"""

    run("git", "config", "user.name", "integritee-policy-automation[bot]")
    run(
        "git",
        "config",
        "user.email",
        "integritee-policy-automation[bot]@users.noreply.github.com",
    )
    run("git", "switch", "-c", branch)
    run("git", "add", str(args.manifest))
    run(
        "git",
        "commit",
        "-m",
        f"feat(policy): add attestation targets from blobheart sources "
        f"{args.blobheart_refs}",
    )
    run("gh", "auth", "setup-git")
    run("git", "push", "--set-upstream", "origin", branch)

    pr_url = run(
        "gh",
        "pr",
        "create",
        "--repo",
        args.repository,
        "--base",
        "main",
        "--head",
        branch,
        "--title",
        f"feat(policy): add targets from Blobheart {short_ref}",
        "--body",
        body,
        capture_output=True,
    ).stdout.strip()
    run(
        "gh",
        "pr",
        "merge",
        "--repo",
        args.repository,
        pr_url,
        "--squash",
        "--delete-branch",
    )
    pr = json.loads(
        run(
            "gh",
            "pr",
            "view",
            "--repo",
            args.repository,
            pr_url,
            "--json",
            "mergeCommit",
            capture_output=True,
        ).stdout
    )
    merge_sha = (pr.get("mergeCommit") or {}).get("oid", "")
    if not SHA_RE.fullmatch(merge_sha):
        raise SystemExit("could not determine manifest PR merge commit")
    with Path(output_path).open("a") as output:
        output.write(f"merge-sha={merge_sha}\n")


def manifest_commit(manifest: Path) -> str:
    """Return the latest commit that changed the manifest."""
    return run(
        "git",
        "log",
        "-1",
        "--format=%H",
        "--",
        str(manifest),
        capture_output=True,
    ).stdout.strip()


def find_release_run(repository: str, release_sha: str) -> int | None:
    """Find the release workflow run for a commit."""
    workflow_runs = json.loads(
        run(
            "gh",
            "run",
            "list",
            "--repo",
            repository,
            "--workflow",
            "release-policy.yaml",
            "--event",
            "push",
            "--limit",
            "50",
            "--json",
            "databaseId,headSha",
            capture_output=True,
        ).stdout
    )
    for workflow_run in workflow_runs:
        if workflow_run["headSha"] == release_sha:
            return int(workflow_run["databaseId"])
    return None


def wait_release(args: argparse.Namespace) -> None:
    """Wait for the matching release workflow to succeed."""
    validate_repository(args.repository)
    release_sha = args.release_sha or manifest_commit(args.manifest)
    if not SHA_RE.fullmatch(release_sha):
        raise SystemExit("could not determine the policy manifest commit")

    deadline = time.monotonic() + args.discovery_timeout
    run_id = None
    while time.monotonic() < deadline:
        run_id = find_release_run(args.repository, release_sha)
        if run_id is not None:
            break
        time.sleep(args.interval)
    if run_id is None:
        raise SystemExit(
            f"timed out waiting for release workflow for {release_sha}"
        )

    print(f"Waiting for production release run {run_id}")
    run(
        "gh",
        "run",
        "watch",
        str(run_id),
        "--repo",
        args.repository,
        "--exit-status",
        "--interval",
        str(args.interval),
    )


def parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    validate_parser = commands.add_parser("validate")
    validate_parser.add_argument("--blobheart-refs", required=True)
    validate_parser.add_argument(
        "--dry-run",
        choices=("true", "false"),
        required=True,
    )
    validate_parser.set_defaults(handler=validate)

    update_parser = commands.add_parser("update")
    update_parser.add_argument("--merged", type=Path, required=True)
    update_parser.add_argument("--manifest", type=Path, required=True)
    update_parser.add_argument("--added", type=int, required=True)
    update_parser.set_defaults(handler=update)

    publish_parser = commands.add_parser("publish-pr")
    publish_parser.add_argument("--manifest", type=Path, required=True)
    publish_parser.add_argument("--blobheart-refs", required=True)
    publish_parser.add_argument("--repository", required=True)
    publish_parser.set_defaults(handler=publish_pr)

    wait_parser = commands.add_parser("wait-release")
    wait_parser.add_argument("--repository", required=True)
    wait_parser.add_argument("--manifest", type=Path, required=True)
    wait_parser.add_argument("--release-sha", default="")
    wait_parser.add_argument("--discovery-timeout", type=int, default=600)
    wait_parser.add_argument("--interval", type=int, default=10)
    wait_parser.set_defaults(handler=wait_release)
    return result


def main() -> None:
    """Dispatch the requested management command."""
    args = parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
