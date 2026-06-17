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
DRIVER_VERSION_PLACEHOLDER = "${NVIDIA_DRIVER_VERSION}"
DEFAULT_TEMPORARY_GCP_TDX_FIRMWARE_ALLOWLIST = (
    Path(__file__).resolve().parents[1]
    / "attestation-policy"
    / "temporary-gcp-tdx-firmware-allowlist.json"
)

DYNAMIC_FIELDS = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]


def to_nvat_driver_version(apt_pkg_version: str) -> str:
    """Strip the apt revision suffix (e.g. ``580.159.04-1ubuntu1`` ->
    ``580.159.04``) to match NVAT's ``x-nvidia-gpu-driver-version``."""
    return apt_pkg_version.split("-", 1)[0]


def resolve_nvidia_driver_version(
    measurements_dir: Path, cvm_artifacts_dir: Path
) -> str:
    """Resolve the driver version from the PodVM image (one image = one
    driver). Reads ``cvm-artifacts/uki/<podvm_image_tag>/measurements.json``
    (cached by fetch-uki.py). Fails if selected models reference different
    PodVM images — one policy emits one ``matches_nvgpu`` block.
    """
    versions: dict[str, str] = {}  # podvm_image_tag -> nvat version
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
            print(f"ERROR: missing {meas_file}; re-run fetch-uki.py", file=sys.stderr)
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


def generate_nonce_rule(nonce: str) -> str:
    """Return a no-op Rego rule that makes every policy upload unique.

    ITA deduplicates by semantic hash (comments are stripped), so we
    need an actual rule — not just a comment — to ensure re-uploads
    (even to the same slot with identical measurements) are accepted.
    """
    return f'integritee_nonce := "{nonce}"'


def load_temporary_gcp_tdx_firmware_allowlist(path: Path | None) -> list[dict]:
    """Load temporary GCP firmware-derived MRTD/RTMR0 pairs.

    This is a short-term compatibility bridge for Google-managed firmware
    rollouts while ITA policy generation still relies on static measurements.
    Remove this once policies consume Google-signed launch endorsements or a
    proper baseline refresh flow.
    """
    if path is None or not path.exists():
        return []

    allowlist = json.loads(path.read_text())
    if not isinstance(allowlist, list):
        print(f"ERROR: {path} must contain a JSON list", file=sys.stderr)
        sys.exit(1)

    for entry in allowlist:
        name = entry.get("name", "<unnamed>")
        for field in ("mrtd", "rtmr0"):
            val = entry.get(field)
            if not isinstance(val, str) or len(val) != 96:
                print(
                    f"ERROR: temporary GCP TDX firmware allowlist entry "
                    f"{name} has invalid {field}",
                    file=sys.stderr,
                )
                sys.exit(1)

    return allowlist


def generate_matches_tdx_block(
    model: str,
    measurements: dict,
    temporary_firmware_label: str | None = None,
) -> str:
    comment = f"# Model: {model}"
    if temporary_firmware_label:
        comment += f" (TEMPORARY GCP firmware allowlist: {temporary_firmware_label})"

    lines = [
        comment,
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


def expand_measurements_for_temporary_gcp_firmware_allowlist(
    measurements: dict,
    temporary_firmware_allowlist: list[dict],
) -> list[tuple[str | None, dict]]:
    variants: list[tuple[str | None, dict]] = [(None, measurements)]
    seen = {(measurements.get("mrtd"), measurements.get("rtmr0"))}

    for firmware in temporary_firmware_allowlist:
        key = (firmware["mrtd"], firmware["rtmr0"])
        if key in seen:
            continue
        seen.add(key)

        variant = dict(measurements)
        variant["mrtd"] = firmware["mrtd"]
        variant["rtmr0"] = firmware["rtmr0"]
        variants.append((firmware.get("name"), variant))

    return variants


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ITA attestation policy")
    parser.add_argument(
        "--measurements-dir",
        required=True,
        help="Directory containing per-model subdirs with measurements.json",
    )
    parser.add_argument(
        "--cvm-artifacts-dir",
        required=True,
        help="Directory with per-model meta.json + cached PodVM measurements",
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
    parser.add_argument(
        "--temporary-gcp-tdx-firmware-allowlist",
        type=Path,
        default=DEFAULT_TEMPORARY_GCP_TDX_FIRMWARE_ALLOWLIST,
        help="Temporary workaround: JSON list of additional GCP "
        "firmware-derived MRTD/RTMR0 pairs to allow. RTMR1-3 remain "
        "model-specific from measurements.json. Remove once we have a "
        "long-term Google endorsement or baseline-refresh flow.",
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
    temporary_firmware_allowlist = load_temporary_gcp_tdx_firmware_allowlist(
        args.temporary_gcp_tdx_firmware_allowlist
    )
    blocks: list[str] = []
    model_names: list[str] = []

    for model_dir in sorted(measurements_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        meas_file = model_dir / "measurements.json"
        if not meas_file.exists():
            continue

        measurements = json.loads(meas_file.read_text())
        for label, variant in expand_measurements_for_temporary_gcp_firmware_allowlist(
            measurements, temporary_firmware_allowlist
        ):
            block = generate_matches_tdx_block(
                model_dir.name, variant, temporary_firmware_label=label
            )
            blocks.append(block)
        model_names.append(model_dir.name)

    if not blocks:
        print("ERROR: No measurement files found", file=sys.stderr)
        sys.exit(1)

    driver_version = resolve_nvidia_driver_version(
        measurements_dir, Path(args.cvm_artifacts_dir)
    )

    policy = template.replace(PLACEHOLDER, "\n\n".join(blocks))
    policy = policy.replace(NONCE_PLACEHOLDER, generate_nonce_rule(args.nonce))
    policy = policy.replace(DRIVER_VERSION_PLACEHOLDER, driver_version)

    if DRIVER_VERSION_PLACEHOLDER in policy:
        print(f"ERROR: {DRIVER_VERSION_PLACEHOLDER} not substituted", file=sys.stderr)
        sys.exit(1)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(policy)
    print(
        f"Generated ITA policy with {len(blocks)} model(s): "
        f"{', '.join(model_names)} (driver={driver_version}) -> {args.output}"
    )


if __name__ == "__main__":
    main()
