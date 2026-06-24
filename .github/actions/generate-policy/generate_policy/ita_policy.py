#!/usr/bin/env python3
"""Generate an ITA attestation policy from per-target measurements.

Reads per-target measurement JSON files and renders a single Rego policy
by replacing the ${TDX_MATCH_BLOCKS} placeholder in the template.
Multiple blocks give Rego logical-OR semantics.
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

PLACEHOLDER = "${TDX_MATCH_BLOCKS}"
NONCE_PLACEHOLDER = "${POLICY_NONCE}"
DRIVER_VERSION_PLACEHOLDER = "${NVIDIA_DRIVER_VERSION}"

DYNAMIC_FIELDS = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]


def to_nvat_driver_version(apt_pkg_version: str) -> str:
    return apt_pkg_version.split("-", 1)[0]


def resolve_nvidia_driver_version(
    measurements_dir: Path, cvm_artifacts_dir: Path
) -> str:
    versions: dict[str, str] = {}
    for model_dir in sorted(measurements_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        meta_file = cvm_artifacts_dir / model_dir.name / "meta.json"
        if not meta_file.exists():
            continue
        meta = json.loads(meta_file.read_text())
        podvm_tag = meta.get("podvm_image_tag")
        if not podvm_tag:
            continue
        meas_file = cvm_artifacts_dir / "uki" / podvm_tag / "measurements.json"
        if not meas_file.exists():
            print(f"ERROR: missing {meas_file}; re-run fetch-uki", file=sys.stderr)
            sys.exit(1)
        pkg_version = json.loads(meas_file.read_text()).get("nvidia_driver_version")
        if not pkg_version:
            print(f"ERROR: {meas_file} has no nvidia_driver_version", file=sys.stderr)
            sys.exit(1)
        versions[podvm_tag] = to_nvat_driver_version(pkg_version)

    if not versions:
        print("ERROR: no podvm_image_tag in any meta.json", file=sys.stderr)
        sys.exit(1)

    unique = set(versions.values())
    if len(unique) > 1:
        details = ", ".join(f"{t}={v}" for t, v in sorted(versions.items()))
        print(f"ERROR: driver mismatch across PodVM images ({details})", file=sys.stderr)
        sys.exit(1)

    return unique.pop()


def generate_nonce_rule() -> str:
    nonce = str(uuid.uuid4())
    return f'integritee_nonce := "{nonce}"'


def generate_matches_tdx_block(model: str, measurements: dict) -> str:
    lines = [
        f"# Model: {model}",
        "matches_tdx if {",
        "    tdx_base_checks",
        "    tdx := input.tdx",
        "",
    ]

    for field in DYNAMIC_FIELDS:
        val = measurements.get(field)
        if val is not None:
            lines.append(f'    tdx.tdx_{field} == "{val}"')

    lines.append("}")
    return "\n".join(lines)


def generate_policy(
    measurements_dir: Path,
    cvm_artifacts_dir: Path,
    template_path: Path,
    output_path: Path,
) -> None:
    template = template_path.read_text()
    if PLACEHOLDER not in template:
        print(f"ERROR: Template does not contain {PLACEHOLDER}", file=sys.stderr)
        sys.exit(1)

    blocks: list[str] = []
    model_names: list[str] = []

    for model_dir in sorted(measurements_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        meas_file = model_dir / "measurements.json"
        if not meas_file.exists():
            continue

        measurements = json.loads(meas_file.read_text())
        block = generate_matches_tdx_block(model_dir.name, measurements)
        blocks.append(block)
        model_names.append(model_dir.name)

    if not blocks:
        print("ERROR: No measurement files found", file=sys.stderr)
        sys.exit(1)

    driver_version = resolve_nvidia_driver_version(
        measurements_dir, cvm_artifacts_dir
    )

    policy = template.replace(PLACEHOLDER, "\n\n".join(blocks))
    policy = policy.replace(NONCE_PLACEHOLDER, generate_nonce_rule())
    policy = policy.replace(DRIVER_VERSION_PLACEHOLDER, driver_version)

    if DRIVER_VERSION_PLACEHOLDER in policy:
        print(f"ERROR: {DRIVER_VERSION_PLACEHOLDER} not substituted", file=sys.stderr)
        sys.exit(1)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(policy)
    print(
        f"Generated ITA policy with {len(blocks)} target(s): "
        f"{', '.join(model_names)} (driver={driver_version}) -> {output_path}"
    )
