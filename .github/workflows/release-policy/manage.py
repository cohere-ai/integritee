#!/usr/bin/env python3
"""Manage Integritee attestation policy releases."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ALPHA_TAG_RE = re.compile(r"v0\.0\.1a([0-9]+)")
VERSION_RE = re.compile(r"v[0-9A-Za-z][0-9A-Za-z._+-]*")
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)
SLOTS = {
    "slot-a": {
        "id": "cbeedffa-e224-4664-b6b4-573fcd4133d3",
        "name": "integritee-policy-a",
    },
    "slot-b": {
        "id": "ecdf9171-2f85-47b4-9941-703118f731a8",
        "name": "integritee-policy-b",
    },
}


def run(*command: str, capture_output: bool = False) -> str:
    """Run a command without invoking a shell."""
    result = subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=capture_output,
    )
    return result.stdout.strip() if capture_output else ""


def next_version() -> str:
    """Return the next v0.0.1 alpha release version."""
    releases = json.loads(
        run(
            "gh",
            "release",
            "list",
            "--limit",
            "100",
            "--json",
            "tagName",
            capture_output=True,
        )
    )
    versions = [
        int(match.group(1))
        for release in releases
        if (match := ALPHA_TAG_RE.fullmatch(release["tagName"]))
    ]
    return f"v0.0.1a{max(versions, default=0) + 1}"


def resolve_version(args: argparse.Namespace) -> None:
    """Validate and output the requested release version."""
    version = args.requested or next_version()
    if not VERSION_RE.fullmatch(version):
        raise SystemExit(f"invalid release version: {version}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        raise SystemExit("GITHUB_OUTPUT is required")
    with Path(github_output).open("a") as output:
        output.write(f"version={version}\n")
    print(f"Release version: {version}")


def initialize_predicate(args: argparse.Namespace) -> None:
    """Create the initial release predicate."""
    commit = run("git", "rev-parse", "HEAD", capture_output=True)
    predicate = {
        "version": args.version,
        "manifest_commit": commit,
        "previous_rekor_log_index": args.previous_log_index,
    }
    args.output.write_text(json.dumps(predicate, indent=2) + "\n")


def detect_last_slot() -> str:
    """Read the ITA slot used by the latest release."""
    try:
        body = run(
            "gh",
            "release",
            "view",
            "--json",
            "body",
            "-q",
            ".body",
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        return ""
    match = re.search(r"ITA Policy Slot.*?`(slot-[ab])", body)
    return match.group(1) if match else ""


def select_slot(args: argparse.Namespace) -> None:
    """Select and emit the target ITA policy slot."""
    if args.override != "auto":
        target = args.override
        print(f"Slot override: {target}", file=sys.stderr)
    else:
        last = detect_last_slot()
        print(f"Last release used: {last or 'none detected'}", file=sys.stderr)
        target = "slot-b" if last == "slot-a" else "slot-a"

    slot = SLOTS[target]
    print(
        f"Targeting: {target} ({slot['name']} / {slot['id']})",
        file=sys.stderr,
    )
    print(f"policy_slot={target}")
    print(f"policy_id={slot['id']}")
    print(f"policy_name={slot['name']}")


def prepare_assets(args: argparse.Namespace) -> None:
    """Collect release assets and generate release notes."""
    if not UUID_RE.fullmatch(args.policy_id):
        raise SystemExit(f"invalid ITA policy ID: {args.policy_id}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    assets = {
        args.policy: "attestation-policy.rego",
        args.manifest: "policy-manifest.yaml",
        args.predicate: "predicate.json",
        args.bundle: "attestation-bundle.sigstore.json",
    }
    for source, destination in assets.items():
        if not source.is_file():
            raise SystemExit(f"release asset does not exist: {source}")
        shutil.copyfile(source, args.output_dir / destination)

    initdata_dir = args.manifest.parent / "initdata"
    if not initdata_dir.is_dir():
        raise SystemExit(f"initdata directory does not exist: {initdata_dir}")
    bundle_path = args.output_dir / "policy-manifest-bundle.tar.gz"
    with tarfile.open(bundle_path, "w:gz") as archive:
        archive.add(args.manifest, arcname="policy-manifest.yaml")
        archive.add(initdata_dir, arcname="initdata")

    sections = []
    if args.reason:
        sections.append(f"**Reason:** {args.reason}")
    sections.extend(
        (
            f"**ITA Policy ID:** `{args.policy_id}`",
            f"**ITA Policy Slot:** `{args.policy_slot}`",
        )
    )
    args.release_notes.write_text("\n\n".join(sections) + "\n")


def parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    version_parser = commands.add_parser("resolve-version")
    version_parser.add_argument("--requested", default="")
    version_parser.set_defaults(handler=resolve_version)

    predicate_parser = commands.add_parser("init-predicate")
    predicate_parser.add_argument("--version", required=True)
    predicate_parser.add_argument("--output", type=Path, required=True)
    predicate_parser.add_argument("--previous-log-index", type=int, default=0)
    predicate_parser.set_defaults(handler=initialize_predicate)

    slot_parser = commands.add_parser("select-slot")
    slot_parser.add_argument(
        "--override",
        choices=("auto", "slot-a", "slot-b"),
        default="auto",
    )
    slot_parser.set_defaults(handler=select_slot)

    assets_parser = commands.add_parser("prepare-assets")
    assets_parser.add_argument("--policy", type=Path, required=True)
    assets_parser.add_argument("--manifest", type=Path, required=True)
    assets_parser.add_argument("--predicate", type=Path, required=True)
    assets_parser.add_argument("--bundle", type=Path, required=True)
    assets_parser.add_argument("--output-dir", type=Path, required=True)
    assets_parser.add_argument("--release-notes", type=Path, required=True)
    assets_parser.add_argument("--policy-id", required=True)
    assets_parser.add_argument(
        "--policy-slot",
        choices=("slot-a", "slot-b"),
        required=True,
    )
    assets_parser.add_argument("--reason", default="")
    assets_parser.set_defaults(handler=prepare_assets)
    return result


def main() -> None:
    """Dispatch the requested release command."""
    args = parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
