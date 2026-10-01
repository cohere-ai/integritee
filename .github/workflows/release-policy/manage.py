#!/usr/bin/env python3
"""Manage Integritee attestation policy releases."""

from __future__ import annotations

import argparse
import base64
import gzip
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

ALPHA_TAG_RE = re.compile(r"v0\.0\.1a([0-9]+)")
VERSION_RE = re.compile(r"v[0-9A-Za-z][0-9A-Za-z._+-]*")
RELEASE_ARCHIVE = "policy-release.tar.gz"
BUNDLE_NAME = "attestation-bundle.sigstore.json"
MANIFEST_NAME = "policy-manifest.yaml"
MAX_ARCHIVE_MEMBER_BYTES = 4 * 1024 * 1024
SIGNER_WORKFLOW = "cohere-ai/integritee/.github/workflows/release-policy.yaml"
PREDICATE_TYPE = "https://cohere.com/attestation-policy/v1"
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)


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


def prepare_assets(args: argparse.Namespace) -> None:
    """Collect release assets and generate release notes."""
    if not UUID_RE.fullmatch(args.policy_id):
        raise SystemExit(f"invalid ITA policy ID: {args.policy_id}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    assets = {
        **{policy: policy.name for policy in args.policy},
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

    signed = [policy.name for policy in args.policy] + [MANIFEST_NAME]
    write_release_archive(
        args.output_dir / RELEASE_ARCHIVE,
        args.output_dir,
        [BUNDLE_NAME, *signed],
    )

    sections = []
    if args.reason:
        sections.append(f"**Reason:** {args.reason}")
    sections.append(f"**ITA Policy ID:** `{args.policy_id}`")
    # Named rather than counted, since a Trustee consumer resolves these by
    # filename and the set of them changes as services are added or dropped.
    policies = ", ".join(f"`{policy.name}`" for policy in args.policy)
    sections.append(f"**Policies:** {policies}")
    args.release_notes.write_text("\n\n".join(sections) + "\n")


def write_release_archive(path: Path, source_dir: Path, names: list[str]) -> None:
    """Write a byte-for-byte reproducible gzip tarball of the named files."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(names):
            data = (source_dir / name).read_bytes()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    with path.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            compressed.write(buffer.getvalue())


def bundle_statement(bundle: bytes) -> dict:
    """Return the in-toto statement from a sigstore bundle's DSSE envelope."""
    envelope = json.loads(bundle)["dsseEnvelope"]
    return json.loads(base64.b64decode(envelope["payload"]))


def extract_release_archive(path: Path, destination: Path) -> list[str]:
    """Extract a release archive, admitting only the files its bundle signs.

    The archive is unsigned packaging, so nothing in it is trusted until the
    bundle verifies; this only guarantees the extracted set is exactly the
    bundle plus its subjects, as flat regular files.
    """
    files: dict[str, bytes] = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name
            if (
                not member.isreg()
                or "/" in name
                or name in {"", ".", ".."}
                or name in files
            ):
                raise SystemExit(f"unexpected archive member: {name!r}")
            if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                raise SystemExit(f"archive member too large: {name}")
            extracted = archive.extractfile(member)
            assert extracted is not None
            files[name] = extracted.read()

    if BUNDLE_NAME not in files:
        raise SystemExit(f"archive is missing {BUNDLE_NAME}")
    subjects = {
        subject["name"] for subject in bundle_statement(files[BUNDLE_NAME])["subject"]
    }
    if set(files) != subjects | {BUNDLE_NAME}:
        raise SystemExit(
            "archive members do not match bundle subjects: "
            f"{sorted(files)} vs {sorted(subjects | {BUNDLE_NAME})}"
        )

    destination.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (destination / name).write_bytes(data)
    return sorted(subjects)


def verify_archive(args: argparse.Namespace) -> None:
    """Verify a release archive the way a consumer does before it is published."""
    extracted = args.work_dir
    subjects = extract_release_archive(args.archive, extracted)
    bundle = extracted / BUNDLE_NAME

    version = bundle_statement(bundle.read_bytes())["predicate"].get("version")
    if version != args.version:
        raise SystemExit(f"bundle predicate version {version!r} != {args.version!r}")

    for subject in subjects:
        run(
            "gh",
            "attestation",
            "verify",
            str(extracted / subject),
            "--bundle",
            str(bundle),
            "--repo",
            args.repo,
            "--predicate-type",
            PREDICATE_TYPE,
            "--signer-workflow",
            SIGNER_WORKFLOW,
        )
    print(f"Verified {args.archive} ({version}): {', '.join(subjects)}")


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

    assets_parser = commands.add_parser("prepare-assets")
    assets_parser.add_argument("--policy", type=Path, nargs="+", required=True)
    assets_parser.add_argument("--manifest", type=Path, required=True)
    assets_parser.add_argument("--predicate", type=Path, required=True)
    assets_parser.add_argument("--bundle", type=Path, required=True)
    assets_parser.add_argument("--output-dir", type=Path, required=True)
    assets_parser.add_argument("--release-notes", type=Path, required=True)
    assets_parser.add_argument("--policy-id", required=True)
    assets_parser.add_argument("--reason", default="")
    assets_parser.set_defaults(handler=prepare_assets)

    verify_parser = commands.add_parser("verify-archive")
    verify_parser.add_argument("--archive", type=Path, required=True)
    verify_parser.add_argument("--version", required=True)
    verify_parser.add_argument("--work-dir", type=Path, required=True)
    verify_parser.add_argument("--repo", default="cohere-ai/integritee")
    verify_parser.set_defaults(handler=verify_archive)
    return result


def main() -> None:
    """Dispatch the requested release command."""
    args = parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
