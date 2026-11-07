"""Entrypoint for the generate-policy Docker action.

Thin shell that parses environment inputs, selects the renderers the caller
asked for, and delegates to the shared pipeline.

Invoked via: python -m generate_policy
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .generate import (
    Renderer,
    clear_policies,
    generate_policy,
    parse_policy_types,
    policy_output_dir,
)
from .ita import ItaRenderer
from .trustee import TrusteeRenderer


def build_renderers(output_dir: Path) -> dict[str, Renderer]:
    """Every policy type this action can emit, by name.

    The full set rather than the requested one: policy-types is validated
    against these names, and every file any of them can write is cleared
    before the run, so an unrequested type cannot leave a stale policy
    behind to be attested as current.

    Adding a service means an entry here, wired to whatever configuration it
    needs, and its outputs declared in action.yml.
    """
    version = os.environ.get("INPUT_VERSION", "")
    nonce = os.environ.get("INPUT_ITA_POLICY_NONCE") == "true"
    return {
        ItaRenderer.name: ItaRenderer(
            baselines_repo=os.environ["BASELINES_REPO"],
            output_dir=output_dir,
            version=version,
            nonce=nonce,
        ),
        TrusteeRenderer.name: TrusteeRenderer(
            output_dir=output_dir,
            policy_version=version,
        ),
    }


def main() -> None:
    manifest_file = os.environ.get("INPUT_MANIFEST_FILE", "")
    if not manifest_file:
        print("ERROR: manifest-file input is required", file=sys.stderr)
        sys.exit(1)

    artifacts_dir = os.environ.get("INPUT_OUTPUT_ARTIFACTS_DIR", "")
    if not artifacts_dir:
        print("ERROR: output-artifacts-dir input is required", file=sys.stderr)
        sys.exit(1)

    predicate_env = os.environ.get("INPUT_PREDICATE_FILE", "")

    renderers = build_renderers(policy_output_dir())
    try:
        requested = parse_policy_types(
            os.environ.get("INPUT_POLICY_TYPES", ""), renderers
        )
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)

    print(f"Generating policies: {', '.join(requested)}")
    clear_policies(renderers.values())

    generate_policy(
        manifest_file=Path(manifest_file),
        podvm_image=os.environ["PODVM_IMAGE"],
        artifacts_dir=Path(artifacts_dir),
        renderers=[renderers[name] for name in requested],
        predicate_file=Path(predicate_env) if predicate_env else None,
    )
    give_to_workspace_owner(policy_output_dir())


def give_to_workspace_owner(directory: Path) -> None:
    """Chown what the container wrote, so later host steps can add files.

    The container runs as root, while steps after it run as the runner user
    who owns the workspace.
    """
    workspace = Path.cwd().stat()
    for root, _, files in os.walk(directory):
        for path in [root, *(os.path.join(root, name) for name in files)]:
            os.chown(path, workspace.st_uid, workspace.st_gid)


main()
