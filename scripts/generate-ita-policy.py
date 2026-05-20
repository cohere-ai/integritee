#!/usr/bin/env python3
"""Generate an ITA attestation policy from measurements.

Reads per-model measurement JSON files and static TDX reference values,
then renders a single Rego policy by replacing the ${TDX_MATCH_BLOCKS}
placeholder in the template with one `matches_tdx if { ... }` block per
model.  Multiple blocks give Rego logical-OR semantics: the policy
matches if ANY model's measurements match.

Usage:
    python generate-ita-policy.py \
        --measurements-dir artifacts/ \
        --template attestation-policy/template.rego \
        --static-ref-vals attestation-policy/tdx-static-ref-vals.yaml \
        --output artifacts/ita-attestation-policy.rego
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

PLACEHOLDER = "${TDX_MATCH_BLOCKS}"

DYNAMIC_FIELDS = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]

STATIC_STRING_FIELDS = [
    "tdx_mrseam",
    "tdx_mrsignerseam",
    "tdx_mrconfigid",
    "tdx_mrowner",
    "tdx_mrownerconfig",
    "tdx_seam_attributes",
    "tdx_td_attributes",
    "tdx_tee_tcb_svn",
]

STATIC_INT_FIELDS = [
    "tdx_seamsvn",
]


def generate_matches_tdx_block(
    model: str,
    measurements: dict,
    static_ref_vals: dict,
) -> str:
    lines = [f"# Model: {model}", "matches_tdx if {", "    tdx := input.tdx", ""]

    for field in DYNAMIC_FIELDS:
        val = measurements.get(field)
        if val is not None:
            lines.append(f'    tdx.tdx_{field} == "{val}"')

    for field in STATIC_STRING_FIELDS:
        val = static_ref_vals.get(field)
        if val is not None:
            lines.append(f'    tdx.{field} == "{val}"')

    lines.append("    tdx.tdx_is_debuggable == false")

    for field in STATIC_INT_FIELDS:
        val = static_ref_vals.get(field)
        if val is not None:
            lines.append(f"    tdx.{field} == {val}")

    lines.append("}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ITA attestation policy")
    parser.add_argument(
        "--measurements-dir",
        required=True,
        help="Directory containing per-model subdirs with measurements.json",
    )
    parser.add_argument(
        "--template",
        required=True,
        help="Path to the base attestation policy template",
    )
    parser.add_argument(
        "--static-ref-vals",
        required=True,
        help="Path to the static TDX reference values YAML file",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output path for the generated policy",
    )
    args = parser.parse_args()

    template = Path(args.template).read_text()
    if PLACEHOLDER not in template:
        print(
            f"ERROR: Template does not contain {PLACEHOLDER}",
            file=sys.stderr,
        )
        sys.exit(1)

    static_ref_vals = yaml.safe_load(Path(args.static_ref_vals).read_text())

    measurements_dir = Path(args.measurements_dir)
    blocks: list[str] = []
    model_names: list[str] = []

    for model_dir in sorted(measurements_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        meas_file = model_dir / "measurements.json"
        if not meas_file.exists():
            continue

        measurements = json.loads(meas_file.read_text())
        block = generate_matches_tdx_block(
            model_dir.name, measurements, static_ref_vals
        )
        blocks.append(block)
        model_names.append(model_dir.name)

    if not blocks:
        print("ERROR: No measurement files found", file=sys.stderr)
        sys.exit(1)

    policy = template.replace(PLACEHOLDER, "\n\n".join(blocks))

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(policy)
    print(
        f"Generated ITA policy with {len(blocks)} model(s): "
        f"{', '.join(model_names)} -> {args.output}"
    )


if __name__ == "__main__":
    main()
