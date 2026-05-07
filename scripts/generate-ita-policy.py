#!/usr/bin/env python3
"""Generate an ITA attestation policy from measurements.

Reads per-model measurement JSON files and produces a single Rego policy
where each model's (MRTD, RTMR0-3) tuple forms a separate match block.
The policy evaluates to true if ANY block matches (logical OR).

Usage:
    python generate-ita-policy.py \
        --measurements-dir artifacts/ \
        --template attestation-policy/template.rego \
        --output artifacts/ita-attestation-policy.rego
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def generate_match_block(model: str, measurements: dict) -> str:
    lines = [
        f"# Model: {model}",
        "match if {",
        "    tdx := input.tdx",
    ]

    if mrtd := measurements.get("mrtd"):
        lines.append(f'    tdx.tdx_mrtd == "{mrtd}"')

    for i in range(4):
        key = f"rtmr{i}"
        if val := measurements.get(key):
            lines.append(f'    tdx.tdx_rtmr{i} == "{val}"')

    lines.append("    tdx.tdx_is_debuggable == false")
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
        "--output",
        required=True,
        help="Output path for the generated policy",
    )
    args = parser.parse_args()

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
        block = generate_match_block(model_dir.name, measurements)
        blocks.append(block)
        model_names.append(model_dir.name)

    if not blocks:
        print("ERROR: No measurement files found", file=sys.stderr)
        sys.exit(1)

    policy_parts = [
        f"# Auto-generated ITA TDX appraisal policy",
        f"# Models: {', '.join(model_names)}",
        "",
        "import rego.v1",
        "",
        "default match := false",
        "",
    ]
    policy_parts.extend(blocks)
    policy_parts.append("")

    policy = "\n".join(policy_parts)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(policy)
    print(f"Generated ITA policy with {len(blocks)} measurement block(s): {args.output}")


if __name__ == "__main__":
    main()
