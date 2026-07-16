"""Generate an ITA attestation policy from a policy manifest.

Orchestrates the full pipeline: fetch baselines/firmware/UKI, compute
measurements per target, render the Rego policy. Returns structured
predicate data so the caller can persist it.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

from .fetch import (
    fetch_baseline_variants,
    fetch_firmware,
    fetch_oci_digest,
    fetch_uki,
)
from .measure import (
    compute_initdata_rtmr3,
    compute_measurements,
    resolve_initdata,
)

PLATFORM_PLACEHOLDER = "${TDX_PLATFORM_MATCH_BLOCKS}"
WORKLOAD_PLACEHOLDER = "${TDX_WORKLOAD_MATCH_BLOCKS}"
NONCE_PLACEHOLDER = "${POLICY_NONCE}"
DRIVER_VERSION_PLACEHOLDER = "${NVIDIA_DRIVER_VERSION}"

DYNAMIC_FIELDS = ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
PLATFORM_FIELDS = ["mrtd", "rtmr0", "rtmr1", "rtmr2"]


def to_nvat_driver_version(apt_pkg_version: str) -> str:
    version = apt_pkg_version.split("-", 1)[0]
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
        raise ValueError(f"invalid NVIDIA driver version: {apt_pkg_version!r}")
    return version


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
        try:
            versions[podvm_tag] = to_nvat_driver_version(pkg_version)
        except ValueError as error:
            print(f"ERROR: {meas_file}: {error}", file=sys.stderr)
            sys.exit(1)

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


def generate_platform_match_block(
    baseline_label: str,
    measurements: dict,
) -> str:
    lines = [
        f"# Platform baseline: {baseline_label}",
        "matches_tdx_platform if {",
        "    tdx := input.tdx",
        "",
    ]
    for field in PLATFORM_FIELDS:
        value = measurements.get(field)
        if value is not None:
            lines.append(f'    tdx.tdx_{field} == "{value}"')
    lines.append("}")
    return "\n".join(lines)


def generate_workload_match_block(
    model: str,
    initdata_label: str,
    rtmr3: str,
) -> str:
    return "\n".join([
        f"# Model: {model} (Initdata: {initdata_label})",
        "matches_tdx_workload if {",
        f'    input.tdx.tdx_rtmr3 == "{rtmr3}"',
        "}",
    ])


def render_policy(
    targets: list[dict],
    nv_driver_version: str,
    template_path: Path,
    output_path: Path,
) -> None:
    """Render the Rego policy file from targets with pre-computed measurements."""
    template = template_path.read_text()
    for placeholder in (PLATFORM_PLACEHOLDER, WORKLOAD_PLACEHOLDER):
        if placeholder not in template:
            print(
                f"ERROR: Template does not contain {placeholder}",
                file=sys.stderr,
            )
            sys.exit(1)

    platform_blocks: list[str] = []
    workload_blocks: list[str] = []
    seen_platforms: set[tuple] = set()
    seen_workloads: set[tuple] = set()
    variant_count = 0
    for target in targets:
        model = target["model"]
        initdata_label = target.get("initdata_sha384", "unknown")[:12]
        baseline_variants = target.get("baseline_variants") or [
            {
                "version": None,
                "firmware_sha384": None,
                "measurements": target["measurements"],
            }
        ]
        for baseline_variant in baseline_variants:
            baseline_label = "current"
            if baseline_variant["version"]:
                firmware = baseline_variant["firmware_sha384"]
                baseline_label = f"{firmware[:12]}/{baseline_variant['version']}"
            variant = baseline_variant["measurements"]
            platform_key = tuple(
                variant.get(field) for field in PLATFORM_FIELDS
            )
            if platform_key not in seen_platforms:
                seen_platforms.add(platform_key)
                platform_blocks.append(
                    generate_platform_match_block(baseline_label, variant)
                )

            workload_key = (model, variant.get("rtmr3"))
            if workload_key not in seen_workloads:
                seen_workloads.add(workload_key)
                workload_blocks.append(generate_workload_match_block(
                    model,
                    initdata_label,
                    variant["rtmr3"],
                ))
            variant_count += 1

    if not variant_count:
        print("ERROR: No targets to generate policy from", file=sys.stderr)
        sys.exit(1)

    policy = template.replace(
        PLATFORM_PLACEHOLDER,
        "\n\n".join(platform_blocks),
    )
    policy = policy.replace(
        WORKLOAD_PLACEHOLDER,
        "\n\n".join(workload_blocks),
    )
    policy = policy.replace(NONCE_PLACEHOLDER, generate_nonce_rule())
    policy = policy.replace(
        DRIVER_VERSION_PLACEHOLDER,
        json.dumps(nv_driver_version),
    )

    if DRIVER_VERSION_PLACEHOLDER in policy:
        print(f"ERROR: {DRIVER_VERSION_PLACEHOLDER} not substituted", file=sys.stderr)
        sys.exit(1)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(policy)

    model_names = [t["model"] for t in targets]
    print(
        f"Generated ITA policy with {variant_count} TDX measurement variant(s) "
        f"from {len(targets)} target(s): "
        f"{', '.join(model_names)} (driver={nv_driver_version}"
        f") -> {output_path}"
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
    platform_measurements_cache: dict[tuple, dict] = {}

    for i, target in enumerate(targets):
        model = target["model"]
        machine_type = target["machine_type"]
        podvm_tag = target["podvm_image_tag"]
        target_dir = artifacts_dir / f"target-{i}"

        print(f"\n{'=' * 60}")
        print(f"Target {i}: {model}")
        print(f"{'=' * 60}")

        baseline_variants = fetch_baseline_variants(
            baselines_repo,
            machine_type,
        )

        podvm_ref = f"{podvm_image}:{podvm_tag}"
        uki_dest = artifacts_dir / "uki" / podvm_tag
        print(f"  UKI: {podvm_tag}")
        fetch_uki(podvm_ref, uki_dest)

        try:
            initdata = resolve_initdata(target, manifest_file)
        except ValueError as error:
            print(f"ERROR: {model}: {error}", file=sys.stderr)
            sys.exit(1)

        measured_variants: list[dict] = []
        for baseline_variant in baseline_variants:
            version = baseline_variant["version"]
            fw_sha384 = baseline_variant["firmware_sha384"]
            baseline_path = (
                artifacts_dir
                / "baselines"
                / machine_type
                / fw_sha384
                / f"{version}.json"
            )
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            baseline_path.write_text(
                json.dumps(baseline_variant["baseline"], indent=2) + "\n"
            )
            baseline_sha256 = hashlib.sha256(
                baseline_path.read_bytes()
            ).hexdigest()

            firmware_path = artifacts_dir / "firmware" / f"{fw_sha384}.fd"
            fetch_firmware(fw_sha384, firmware_path)

            variant_output_dir = target_dir / fw_sha384 / version
            cache_key = (
                machine_type,
                target["ram_gib"],
                podvm_tag,
                fw_sha384,
                baseline_sha256,
            )
            platform_measurements = platform_measurements_cache.get(cache_key)
            if platform_measurements is None:
                print(
                    f"  Computing platform measurements for "
                    f"{fw_sha384[:12]}/{version}..."
                )
                computed = compute_measurements(
                    ram_gib=target["ram_gib"],
                    initdata=initdata,
                    firmware_path=firmware_path,
                    baseline_path=baseline_path,
                    uki_path=uki_dest / "BOOTX64.EFI",
                    disk_path=uki_dest / "disk.tar.gz",
                    output_dir=variant_output_dir,
                )
                platform_measurements = {
                    field: value
                    for field, value in computed.items()
                    if field != "rtmr3"
                }
                platform_measurements_cache[cache_key] = platform_measurements
            else:
                print(
                    f"  Reusing platform measurements for "
                    f"{fw_sha384[:12]}/{version}"
                )

            measurements = {
                **platform_measurements,
                "rtmr3": compute_initdata_rtmr3(initdata),
            }
            variant_output_dir.mkdir(parents=True, exist_ok=True)
            (variant_output_dir / "initdata.toml").write_bytes(initdata)
            (variant_output_dir / "measurements.json").write_text(
                json.dumps(measurements, indent=2) + "\n"
            )
            measured_variants.append({
                "version": version,
                "firmware_sha384": fw_sha384,
                "baseline_ref": baseline_variant["baseline_ref"],
                "baseline_sha256": baseline_sha256,
                "measurements": measurements,
            })

        primary_variant = measured_variants[0]
        target["measurements"] = primary_variant["measurements"]
        target["baseline_variants"] = measured_variants
        initdata_hash = hashlib.sha384(initdata).hexdigest()

        predicate_targets.append({
            **target,
            "podvm_image": podvm_ref,
            "podvm_digest": fetch_oci_digest(podvm_ref),
            "firmware_sha384": primary_variant["firmware_sha384"],
            "baseline_ref": primary_variant["baseline_ref"],
            "baseline_sha256": primary_variant["baseline_sha256"],
            "initdata_hash": initdata_hash,
        })

    print(f"\n{'=' * 60}")
    print("Generating ITA policy")
    print(f"{'=' * 60}")
    nv_driver_version = resolve_nvidia_driver_version(targets, artifacts_dir)
    render_policy(
        targets,
        nv_driver_version,
        template_path,
        policy_output,
    )

    if predicate_file:
        predicate = json.loads(predicate_file.read_text()) if predicate_file.exists() else {}
        predicate["cvm_measure_version"] = get_cvm_measure_version()
        predicate["targets"] = predicate_targets
        predicate_file.write_text(json.dumps(predicate, indent=2) + "\n")
        print(f"Updated predicate: {predicate_file}")
