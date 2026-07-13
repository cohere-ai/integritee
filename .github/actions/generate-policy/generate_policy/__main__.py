"""Entrypoint for the generate-policy Docker action.

Thin shell that parses environment inputs and delegates to generate.py.

Invoked via: python -m generate_policy
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .generate import generate_policy


def main() -> None:
    manifest_file = os.environ.get("INPUT_MANIFEST_FILE", "")
    if not manifest_file:
        print("ERROR: manifest-file input is required", file=sys.stderr)
        sys.exit(1)

    artifacts_dir = os.environ.get("INPUT_OUTPUT_ARTIFACTS_DIR", "")
    if not artifacts_dir:
        print("ERROR: output-artifacts-dir input is required", file=sys.stderr)
        sys.exit(1)

    policy_file = os.environ.get("INPUT_OUTPUT_POLICY_FILE", "")
    if not policy_file:
        print("ERROR: output-policy-file input is required", file=sys.stderr)
        sys.exit(1)

    predicate_env = os.environ.get("INPUT_PREDICATE_FILE", "")
    allowlist_env = os.environ.get(
        "INPUT_TEMPORARY_GCP_TDX_FIRMWARE_ALLOWLIST", ""
    ).strip()

    generate_policy(
        manifest_file=Path(manifest_file),
        baselines_repo=os.environ["BASELINES_REPO"],
        podvm_image=os.environ["PODVM_IMAGE"],
        artifacts_dir=Path(artifacts_dir),
        template_path=Path(__file__).parent / "policy-template.rego",
        policy_output=Path(policy_file),
        predicate_file=Path(predicate_env) if predicate_env else None,
        temporary_gcp_tdx_firmware_allowlist=(
            Path(allowlist_env) if allowlist_env else None
        ),
    )


main()
