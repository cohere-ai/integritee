#!/usr/bin/env python3
"""Generate an ITA attestation policy from measurements.

Reads per-model measurement JSON files and renders a single Rego policy
by replacing the ${TDX_MATCH_BLOCKS} placeholder in the template with
one `matches_tdx if { ... }` block per model.  Multiple blocks give
Rego logical-OR semantics: the policy matches if ANY model's measurements
match.  Static TDX reference values are checked via `tdx_base_checks`
which is defined in the template itself.

ITA deduplicates policies by semantic content hash (comments stripped).
A no-op nonce rule is injected via --nonce to guarantee every upload
has a unique hash, even when re-uploading the same measurements to the
same slot.

Usage:
    python generate-ita-policy.py \
        --measurements-dir artifacts/ \
        --template attestation-policy/template.rego \
        --nonce "12345678" \
        --output artifacts/ita-attestation-policy.rego
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PLACEHOLDER = "${TDX_MATCH_BLOCKS}"
NONCE_PLACEHOLDER = "${POLICY_NONCE}"

DYNAMIC_FIELDS = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]


def generate_nonce_rule(nonce: str) -> str:
    """Return a no-op Rego rule that makes every policy upload unique.

    ITA deduplicates by semantic hash (comments are stripped), so we
    need an actual rule — not just a comment — to ensure re-uploads
    (even to the same slot with identical measurements) are accepted.
    """
    return f'model_integrity_nonce := "{nonce}"'


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
    parser.add_argument(
        "--nonce",
        required=True,
        help="Unique value injected as a no-op Rego rule so ITA's "
        "content-dedup hash differs on every upload (e.g. a CI "
        "run ID or timestamp)",
    )
    args = parser.parse_args()

    template = Path(args.template).read_text()
    if PLACEHOLDER not in template:
        print(
            f"ERROR: Template does not contain {PLACEHOLDER}",
            file=sys.stderr,
        )
        sys.exit(1)

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
        block = generate_matches_tdx_block(model_dir.name, measurements)
        blocks.append(block)
        model_names.append(model_dir.name)

    if not blocks:
        print("ERROR: No measurement files found", file=sys.stderr)
        sys.exit(1)

    policy = template.replace(PLACEHOLDER, "\n\n".join(blocks))
    policy = policy.replace(NONCE_PLACEHOLDER, generate_nonce_rule(args.nonce))

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(policy)
    print(
        f"Generated ITA policy with {len(blocks)} model(s): "
        f"{', '.join(model_names)} -> {args.output}"
    )


if __name__ == "__main__":
    main()
