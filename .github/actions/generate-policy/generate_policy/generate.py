"""Generate an ITA attestation policy from a policy manifest.

Orchestrates the full pipeline: fetch baselines/firmware/UKI, compute
measurements per target, render the Rego policy. Returns structured
predicate data so the caller can persist it.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import uuid
from pathlib import Path

from .fetch import fetch_baseline, fetch_firmware, fetch_oci_digest, fetch_uki
from .measure import compute_measurements

PLACEHOLDER = "${TDX_MATCH_BLOCKS}"
NONCE_PLACEHOLDER = "${POLICY_NONCE}"
DRIVER_VERSION_PLACEHOLDER = "${NVIDIA_DRIVER_VERSION}"

DYNAMIC_FIELDS = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]


def to_nvat_driver_version(apt_pkg_version: str) -> str:
    return apt_pkg_version.split("-", 1)[0]


def resolve_nvidia_driver_version(
    targets: list[dict], artifacts_dir: Path
) -> str:
    """Resolve the NVIDIA driver version from UKI measurements.json files."""
    versions: dict[str, str] = {}
    for target in targets:
        podvm_tag = target.get("podvm_image_tag")
        if not podvm_tag or podvm_tag in versions:
            continue
        meas_file = artifacts_dir / "uki" / podvm_tag / "measurements.json"
        if not meas_file.exists():
            print(f"ERROR: missing {meas_file}; re-run fetch-uki", file=sys.stderr)
            sys.exit(1)
        pkg_version = json.loads(meas_file.read_text()).get("nvidia_driver_version")
        if not pkg_version:
            print(f"ERROR: {meas_file} has no nvidia_driver_version", file=sys.stderr)
            sys.exit(1)
        versions[podvm_tag] = to_nvat_driver_version(pkg_version)

    if not versions:
        print("ERROR: no podvm_image_tag in any target", file=sys.stderr)
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


def generate_matches_tdx_block(
    index: int, model: str, measurements: dict
) -> str:
    lines = [
        f"# Target {index}: {model}",
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


def render_policy(
    targets: list[dict],
    nv_driver_version: str,
    template_path: Path,
    output_path: Path,
) -> None:
    """Render the Rego policy file from targets with pre-computed measurements."""
    template = template_path.read_text()
    if PLACEHOLDER not in template:
        print(f"ERROR: Template does not contain {PLACEHOLDER}", file=sys.stderr)
        sys.exit(1)

    blocks: list[str] = []
    for i, target in enumerate(targets):
        measurements = target["measurements"]
        block = generate_matches_tdx_block(i, target["model"], measurements)
        blocks.append(block)

    if not blocks:
        print("ERROR: No targets to generate policy from", file=sys.stderr)
        sys.exit(1)

    policy = template.replace(PLACEHOLDER, "\n\n".join(blocks))
    policy = policy.replace(NONCE_PLACEHOLDER, generate_nonce_rule())
    policy = policy.replace(DRIVER_VERSION_PLACEHOLDER, nv_driver_version)

    if DRIVER_VERSION_PLACEHOLDER in policy:
        print(f"ERROR: {DRIVER_VERSION_PLACEHOLDER} not substituted", file=sys.stderr)
        sys.exit(1)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(policy)

    model_names = [t["model"] for t in targets]
    print(
        f"Generated ITA policy with {len(blocks)} target(s): "
        f"{', '.join(model_names)} (driver={driver_version}) -> {output_path}"
    )


def get_cvm_measure_version() -> str:
    try:
        out = subprocess.run(
            ["pip", "show", "cvm-measure"],
            capture_output=True, text=True,
        ).stdout
        return next(
            (line.split(":")[1].strip() for line in out.splitlines()
             if line.startswith("Version:")), "unknown"
        )
    except Exception:
        return "unknown"


def generate_policy(
    manifest_file: Path,
    baselines_repo: str,
    podvm_image: str,
    artifacts_dir: Path,
    template_path: Path,
    policy_output: Path,
    predicate_file: Path | None = None,
) -> None:
    """Run the full pipeline: read manifest, fetch, measure, render policy, update predicate.

    If predicate_file is provided and exists, it is read, updated in place
    with cvm_measure_version and per-target data, and written back.
    """
    if not manifest_file.exists():
        print(f"ERROR: manifest file not found: {manifest_file}", file=sys.stderr)
        sys.exit(1)

    import yaml
    doc = yaml.safe_load(manifest_file.read_text()) or {}
    targets = doc.get("targets", [])
    if not targets:
        print("ERROR: no targets in manifest", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(targets)} targets from {manifest_file}")

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    predicate_targets: list[dict] = []

    for i, target in enumerate(targets):
        model = target["model"]
        machine_type = target["machine_type"]
        podvm_tag = target["podvm_image_tag"]
        target_dir = artifacts_dir / f"target-{i}"

        print(f"\n{'=' * 60}")
        print(f"Target {i}: {model}")
        print(f"{'=' * 60}")

        baseline_path = artifacts_dir / "baselines" / f"{machine_type}.json"
        if baseline_path.exists():
            baseline = json.loads(baseline_path.read_text())
        else:
            baseline = fetch_baseline(baselines_repo, machine_type)
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            baseline_path.write_text(json.dumps(baseline, indent=2))

        fw_sha384 = baseline["firmware_sha384"]
        firmware_path = artifacts_dir / "firmware" / f"{fw_sha384}.fd"
        fetch_firmware(fw_sha384, firmware_path)

        podvm_ref = f"{podvm_image}:{podvm_tag}"
        uki_dest = artifacts_dir / "uki" / podvm_tag
        print(f"  UKI: {podvm_tag}")
        fetch_uki(podvm_ref, uki_dest)

        print(f"  Computing measurements...")
        measurements = compute_measurements(
            ram_gib=target["ram_gib"],
            initdata_b64=target["initdata_b64"],
            firmware_path=firmware_path,
            baseline_path=baseline_path,
            uki_path=uki_dest / "BOOTX64.EFI",
            disk_path=uki_dest / "disk.tar.gz",
            output_dir=target_dir,
        )

        target["measurements"] = measurements

        initdata_toml = target_dir / "initdata.toml"
        initdata_hash = ""
        if initdata_toml.exists():
            initdata_hash = hashlib.sha384(initdata_toml.read_bytes()).hexdigest()

        predicate_targets.append({
            **target,
            "podvm_image": podvm_ref,
            "podvm_digest": fetch_oci_digest(podvm_ref),
            "firmware_sha384": fw_sha384,
            "baseline_ref": f"{baselines_repo}/baselines/gcp/tdx/{machine_type}.json",
            "baseline_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
            "initdata_hash": initdata_hash,
        })

    print(f"\n{'=' * 60}")
    print("Generating ITA policy")
    print(f"{'=' * 60}")
    nv_driver_version = resolve_nvidia_driver_version(targets, artifacts_dir)
    render_policy(targets, nv_driver_version, template_path, policy_output)

    if predicate_file:
        predicate = json.loads(predicate_file.read_text()) if predicate_file.exists() else {}
        predicate["cvm_measure_version"] = get_cvm_measure_version()
        predicate["targets"] = predicate_targets
        predicate_file.write_text(json.dumps(predicate, indent=2) + "\n")
        print(f"Updated predicate: {predicate_file}")
