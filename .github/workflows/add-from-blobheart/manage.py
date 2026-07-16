#!/usr/bin/env python3
"""Manage Blobheart policy manifest updates and releases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
SHA_RE = re.compile(r"[0-9a-f]{40}")
SHA384_FILE_RE = re.compile(r"[0-9a-f]{96}\.toml")
BLOBHEART_REPOSITORY = "cohere-ai/blobheart"
BLOBHEART_DEFAULT_BRANCH = "main"


def run(
    *command: str,
    check: bool = True,
    capture_output: bool = False,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command without invoking a shell."""
    return subprocess.run(
        command,
        check=check,
        text=True,
        capture_output=capture_output,
        timeout=timeout,
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
    for ref in refs:
        comparison = run(
            "gh",
            "api",
            (
                f"/repos/{BLOBHEART_REPOSITORY}/compare/"
                f"{ref}...{BLOBHEART_DEFAULT_BRANCH}"
            ),
            "--jq",
            ".status",
            capture_output=True,
            timeout=30,
        ).stdout.strip()
        if comparison not in {"ahead", "identical"}:
            raise SystemExit(
                f"Blobheart commit {ref} is not an ancestor of "
                f"{BLOBHEART_DEFAULT_BRANCH}"
            )


def install_initdata(source_dir: Path, destination_dir: Path) -> None:
    """Copy content-addressed initdata files into the repository."""
    if not source_dir.is_dir():
        raise SystemExit(f"initdata directory does not exist: {source_dir}")
    destination_dir.mkdir(parents=True, exist_ok=True)
    for source in source_dir.iterdir():
        if not source.is_file() or not SHA384_FILE_RE.fullmatch(source.name):
            raise SystemExit(f"unexpected initdata file: {source}")
        source_initdata = source.read_bytes()
        expected_digest = source.stem
        if hashlib.sha384(source_initdata).hexdigest() != expected_digest:
            raise SystemExit(f"initdata digest does not match filename: {source.name}")

        destination = destination_dir / source.name
        if destination.exists() and destination.read_bytes() != source_initdata:
            raise SystemExit(f"initdata digest collision: {source.name}")
        if not destination.exists():
            shutil.copyfile(source, destination)


def update(args: argparse.Namespace) -> None:
    """Install the merged manifest and report changes."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        raise SystemExit("GITHUB_OUTPUT is required")
    shutil.copyfile(args.merged, args.manifest)
    install_initdata(args.initdata_source, args.initdata_dir)

    status_lines = run(
        "git",
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        capture_output=True,
    ).stdout.splitlines()
    changed_files = [line[3:] for line in status_lines]
    initdata_prefix = f"{args.initdata_dir}/"
    unexpected = [
        path
        for path in changed_files
        if path != str(args.manifest) and not path.startswith(initdata_prefix)
    ]
    if unexpected:
        raise SystemExit(f"unexpected changed files: {unexpected}")

    changed = bool(changed_files)
    with Path(output_path).open("a") as output:
        output.write(f"changed={str(changed).lower()}\n")
    if not changed:
        print("No changes to manifest; all targets already track this ref")
        return

    print(
        f"Manifest updated: {args.added} new targets; "
        "sources updated on deduplicated targets"
    )
    run("git", "diff", "--", str(args.manifest))
    for path in changed_files:
        if path.startswith(initdata_prefix):
            print(f"Added initdata: {path}")


def publish(args: argparse.Namespace) -> None:
    """Commit and push the generated manifest directly."""
    refs = args.blobheart_refs.split()
    if not refs or any(not SHA_RE.fullmatch(ref) for ref in refs):
        raise SystemExit("blobheart refs must be 40-character lowercase SHAs")
    validate_repository(args.repository)

    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        raise SystemExit("GITHUB_OUTPUT is required")

    run("git", "config", "user.name", "integritee-policy-automation[bot]")
    run(
        "git",
        "config",
        "user.email",
        "integritee-policy-automation[bot]@users.noreply.github.com",
    )
    run("git", "add", str(args.manifest), str(args.initdata_dir))
    run(
        "git",
        "commit",
        "-m",
        f"feat(policy): add attestation targets from blobheart sources "
        f"{args.blobheart_refs}",
    )
    run("gh", "auth", "setup-git")
    run("git", "push", "origin", "HEAD")
    release_sha = run(
        "git",
        "rev-parse",
        "HEAD",
        capture_output=True,
    ).stdout.strip()
    if not SHA_RE.fullmatch(release_sha):
        raise SystemExit("could not determine manifest commit")
    with Path(output_path).open("a") as output:
        output.write(f"release-sha={release_sha}\n")


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
    update_parser.add_argument("--initdata-source", type=Path, required=True)
    update_parser.add_argument("--initdata-dir", type=Path, required=True)
    update_parser.add_argument("--added", type=int, required=True)
    update_parser.set_defaults(handler=update)

    publish_parser = commands.add_parser("publish")
    publish_parser.add_argument("--manifest", type=Path, required=True)
    publish_parser.add_argument("--initdata-dir", type=Path, required=True)
    publish_parser.add_argument("--blobheart-refs", required=True)
    publish_parser.add_argument("--repository", required=True)
    publish_parser.set_defaults(handler=publish)

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
