#!/usr/bin/env python3
"""Manage staging attestation policy releases.

Staging releases let a Blobheart change be attested end to end before it is
merged, without touching production. They are isolated from production on
every axis a consumer checks:

- tag: ``staging-<run_id>-<attempt>``, never a ``v0.0.1aN`` production version,
  and published as a prerelease that is never marked latest;
- signer: release-policy-staging.yaml in the ``staging`` environment, with
  its own predicate type, so a production verifier rejects the bundle;
- ITA: a separate account (STAGING_ITA_* secrets) and policy, so the
  production policy is never read or written.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

STAGING_TAG_RE = re.compile(r"staging-[0-9]+-[0-9]+")
SHA_RE = re.compile(r"[0-9a-f]{40}")
RUN_ID_RE = re.compile(r"[0-9]+")
ARTIFACT_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
INITDATA_FILE_RE = re.compile(r"[0-9a-f]{96}\.toml")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)

# The production ITA policy. Staging must never upload to it.
PRODUCTION_ITA_POLICY_ID = "cbeedffa-e224-4664-b6b4-573fcd4133d3"
STAGING_PREDICATE_TYPE = "https://cohere.com/attestation-policy/staging/v1"
STAGING_SIGNER_WORKFLOW = ".github/workflows/release-policy-staging.yaml"
STAGING_ENVIRONMENT = "staging"
DEFAULT_KEEP = 20


def run(*command: str, capture_output: bool = False) -> str:
    """Run a command without invoking a shell."""
    result = subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=capture_output,
    )
    return result.stdout.strip() if capture_output else ""


def github_output(**values: str) -> None:
    """Append step outputs."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        raise SystemExit("GITHUB_OUTPUT is required")
    with Path(path).open("a") as output:
        for name, value in values.items():
            if "\n" in value:
                raise SystemExit(f"output {name} must be a single line")
            output.write(f"{name}={value}\n")


def staging_version(run_id: str, run_attempt: str) -> str:
    """Return the staging tag for a workflow run."""
    version = f"staging-{run_id}-{run_attempt}"
    if not STAGING_TAG_RE.fullmatch(version):
        raise SystemExit(f"invalid staging version: {version}")
    return version


def resolve_inputs(args: argparse.Namespace) -> None:
    """Validate the manifest source and output the staging version.

    Exactly one source: Blobheart commit SHAs to derive from, or a Blobheart
    workflow run whose artifact already holds a derived manifest. Unlike the
    production import, SHAs need not be on Blobheart main: testing an
    unmerged change is the point.
    """
    refs = args.blobheart_refs.split()
    run_id = args.manifest_run_id.strip()
    if bool(refs) == bool(run_id):
        raise SystemExit(
            "set exactly one of blobheart_refs or manifest_run_id"
        )
    invalid = [ref for ref in refs if not SHA_RE.fullmatch(ref)]
    if invalid:
        raise SystemExit(f"invalid Blobheart commit SHA: {invalid[0]}")
    if run_id and not RUN_ID_RE.fullmatch(run_id):
        raise SystemExit(f"invalid Blobheart run ID: {run_id}")
    if run_id and not ARTIFACT_NAME_RE.fullmatch(args.manifest_artifact):
        raise SystemExit(f"invalid artifact name: {args.manifest_artifact}")

    version = staging_version(args.run_id, args.run_attempt)
    github_output(
        version=version,
        source="run" if run_id else "refs",
    )
    print(f"Staging version: {version}")


def check_artifact_manifest(args: argparse.Namespace) -> None:
    """Check a downloaded Blobheart manifest artifact before it is merged.

    The artifact is the derive-manifest action's output: a manifest whose
    targets name ``initdata/<sha384>.toml``, plus that initdata directory.
    Nothing else may be in it, and every initdata file must match its content
    address, so a malformed artifact fails here rather than mid-merge.
    """
    manifest = args.artifact_dir / "policy-manifest.yaml"
    initdata = args.artifact_dir / "initdata"
    if not manifest.is_file() or manifest.is_symlink():
        raise SystemExit("artifact has no policy-manifest.yaml")
    if not initdata.is_dir() or initdata.is_symlink():
        raise SystemExit("artifact has no initdata directory")

    unexpected = [
        path.name
        for path in args.artifact_dir.iterdir()
        if path.name not in {"policy-manifest.yaml", "initdata"}
    ]
    if unexpected:
        raise SystemExit(f"unexpected artifact entries: {sorted(unexpected)}")

    files = list(initdata.iterdir())
    if not files:
        raise SystemExit("artifact initdata directory is empty")
    for source in files:
        if (
            source.is_symlink()
            or not source.is_file()
            or not INITDATA_FILE_RE.fullmatch(source.name)
        ):
            raise SystemExit(f"unexpected initdata file: {source.name}")
        if hashlib.sha384(source.read_bytes()).hexdigest() != source.stem:
            raise SystemExit(
                f"initdata digest does not match filename: {source.name}"
            )

    github_output(
        manifest_file=str(manifest),
        initdata_dir=str(initdata),
    )


def check_ita_target(args: argparse.Namespace) -> None:
    """Refuse to publish unless the ITA target is unmistakably staging.

    The secrets have staging-only names, defined only in the staging
    environment, so a missing one fails here instead of falling back to the
    repository-level production key.
    """
    if not args.api_key:
        raise SystemExit(
            "STAGING_ITA_ADMIN_API_KEY is not set in the staging environment"
        )
    if not args.api_url:
        raise SystemExit(
            "STAGING_ITA_API_URL is not set in the staging environment"
        )
    if args.policy_id == PRODUCTION_ITA_POLICY_ID:
        raise SystemExit("STAGING_ITA_POLICY_ID is the production ITA policy")
    if args.policy_id and not UUID_RE.fullmatch(args.policy_id):
        raise SystemExit(f"invalid STAGING_ITA_POLICY_ID: {args.policy_id}")
    if not args.policy_id:
        print(
            "STAGING_ITA_POLICY_ID is unset: this run creates the staging "
            "policy. Set the variable to the printed ID afterwards."
        )


def annotate_predicate(args: argparse.Namespace) -> None:
    """Record that the predicate is staging and what it was built from."""
    predicate = json.loads(args.predicate.read_text())
    predicate["channel"] = STAGING_ENVIRONMENT
    predicate["blobheart_refs"] = args.blobheart_refs.split()
    if args.manifest_run_id:
        predicate["blobheart_manifest_run"] = {
            "repository": "cohere-ai/blobheart",
            "run_id": int(args.manifest_run_id),
            "artifact": args.manifest_artifact,
        }
    args.predicate.write_text(json.dumps(predicate, indent=2) + "\n")


def consumer_config(version: str, repository: str) -> dict:
    """The TNG policy_source that pins a staging release."""
    return {
        "url": f"https://github.com/{repository}/releases/download/{version}",
        "version": version,
        "provenance": {
            "repo": repository,
            "signer_workflow": STAGING_SIGNER_WORKFLOW,
            "source_ref": "refs/heads/main",
            "predicate_type": STAGING_PREDICATE_TYPE,
            "environment": STAGING_ENVIRONMENT,
        },
    }


def release_notes(args: argparse.Namespace) -> None:
    """Prefix release notes with the staging warning and consumer config."""
    if not REPOSITORY_RE.fullmatch(args.repository):
        raise SystemExit("repository must be OWNER/NAME")
    config = consumer_config(args.version, args.repository)
    banner = (
        "**Staging release.** Not for production: signed by "
        f"`{STAGING_SIGNER_WORKFLOW}` in the `{STAGING_ENVIRONMENT}` "
        f"environment with predicate type `{STAGING_PREDICATE_TYPE}`, and "
        "uploaded to the staging ITA account.\n\n"
        "TNG `policy_source` for this release:\n\n"
        f"```json\n{json.dumps(config, indent=2)}\n```\n\n"
    )
    args.notes.write_text(banner + args.notes.read_text())


def prune(args: argparse.Namespace) -> None:
    """Delete all but the newest staging prereleases."""
    if args.keep < 1:
        raise SystemExit("--keep must be at least 1")
    releases = json.loads(
        run(
            "gh",
            "release",
            "list",
            "--limit",
            "200",
            "--json",
            "tagName,isPrerelease,createdAt",
            capture_output=True,
        )
    )
    staging = sorted(
        (
            release
            for release in releases
            if release["isPrerelease"]
            and STAGING_TAG_RE.fullmatch(release["tagName"])
        ),
        key=lambda release: release["createdAt"],
        reverse=True,
    )
    for release in staging[args.keep:]:
        print(f"Deleting staging release {release['tagName']}")
        run(
            "gh",
            "release",
            "delete",
            release["tagName"],
            "--yes",
            "--cleanup-tag",
        )


def parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    inputs = commands.add_parser("resolve-inputs")
    inputs.add_argument("--blobheart-refs", default="")
    inputs.add_argument("--manifest-run-id", default="")
    inputs.add_argument("--manifest-artifact", default="")
    inputs.add_argument("--run-id", required=True)
    inputs.add_argument("--run-attempt", required=True)
    inputs.set_defaults(handler=resolve_inputs)

    artifact = commands.add_parser("check-artifact-manifest")
    artifact.add_argument("--artifact-dir", type=Path, required=True)
    artifact.set_defaults(handler=check_artifact_manifest)

    ita = commands.add_parser("check-ita-target")
    ita.add_argument("--api-key", default="")
    ita.add_argument("--api-url", default="")
    ita.add_argument("--policy-id", default="")
    ita.set_defaults(handler=check_ita_target)

    predicate = commands.add_parser("annotate-predicate")
    predicate.add_argument("--predicate", type=Path, required=True)
    predicate.add_argument("--blobheart-refs", default="")
    predicate.add_argument("--manifest-run-id", default="")
    predicate.add_argument("--manifest-artifact", default="")
    predicate.set_defaults(handler=annotate_predicate)

    notes = commands.add_parser("release-notes")
    notes.add_argument("--notes", type=Path, required=True)
    notes.add_argument("--version", required=True)
    notes.add_argument("--repository", required=True)
    notes.set_defaults(handler=release_notes)

    prune_parser = commands.add_parser("prune")
    prune_parser.add_argument("--keep", type=int, default=DEFAULT_KEEP)
    prune_parser.set_defaults(handler=prune)
    return result


def main() -> None:
    """Dispatch the requested staging command."""
    args = parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
