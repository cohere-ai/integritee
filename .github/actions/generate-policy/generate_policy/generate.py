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
from dataclasses import dataclass, field
from pathlib import Path

import yaml

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

PLATFORM_FIELDS = ["mrtd", "rtmr0", "rtmr1", "rtmr2"]
MEASUREMENT_RE = re.compile(r"^[0-9a-f]{96,128}$")

MACHINE_TYPES_PATH = Path(__file__).parent / "machine-types.yaml"


def validate_measurement(field: str, value: object) -> str:
    if not isinstance(value, str) or not MEASUREMENT_RE.fullmatch(value):
        raise ValueError(f"invalid or missing TDX measurement: {field}")
    return value


def load_machine_types() -> dict[str, dict]:
    """Load the shared machine type table."""
    return yaml.safe_load(MACHINE_TYPES_PATH.read_text()) or {}


def resolve_machine(target: dict, machine_types: dict[str, dict]) -> dict:
    """Return the machine-types entry backing a target."""
    machine_type = target["machine_type"]
    machine = machine_types.get(machine_type)
    if machine is None:
        raise ValueError(
            f"unknown machine type '{machine_type}' -- update machine-types.yaml"
        )
    return machine


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
    values = {
        field: validate_measurement(field, measurements.get(field))
        for field in PLATFORM_FIELDS
    }
    lines = [
        f"# Platform baseline: {baseline_label}",
        "matches_tdx_platform if {",
        "    tdx := input.tdx",
        "",
    ]
    for field in PLATFORM_FIELDS:
        lines.append(
            f"    tdx.tdx_{field} == {json.dumps(values[field])}"
        )
    lines.append("}")
    return "\n".join(lines)


def generate_workload_match_block(
    model: str,
    initdata_label: str,
    rtmr3: str,
) -> str:
    rtmr3 = validate_measurement("rtmr3", rtmr3)
    return "\n".join([
        f"# Model: {model} (Initdata: {initdata_label})",
        "matches_tdx_workload if {",
        f"    input.tdx.tdx_rtmr3 == {json.dumps(rtmr3)}",
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


@dataclass(frozen=True)
class PreparedBaseline:
    version: str
    firmware_sha384: str
    ref: str
    path: Path
    sha256: str
    firmware_path: Path


@dataclass(frozen=True)
class PodVMArtifact:
    uki_path: Path
    digest: str


@dataclass
class GenerationContext:
    """Configuration and memoized artifacts for one generation run."""

    # Run configuration.
    baselines_repo: str
    podvm_image: str
    artifacts_dir: Path

    # Per-run caches. Callers use the methods below, not these dictionaries.
    _baselines: dict[str, list[PreparedBaseline]] = field(
        default_factory=dict, init=False, repr=False
    )
    _firmware: dict[str, Path] = field(
        default_factory=dict, init=False, repr=False
    )
    _podvms: dict[str, PodVMArtifact] = field(
        default_factory=dict, init=False, repr=False
    )
    _platform_measurements: dict[tuple, dict] = field(
        default_factory=dict, init=False, repr=False
    )

    def _get_firmware(self, firmware_sha384: str) -> Path:
        path = self._firmware.get(firmware_sha384)
        if path is None:
            path = (
                self.artifacts_dir
                / "firmware"
                / f"{firmware_sha384}.fd"
            )
            fetch_firmware(firmware_sha384, path)
            self._firmware[firmware_sha384] = path
        return path

    def get_baselines(self, machine_type: str) -> list[PreparedBaseline]:
        baselines = self._baselines.get(machine_type)
        if baselines is not None:
            print(f"  Reusing baseline variants for {machine_type}")
            return baselines

        baselines = []
        for variant in fetch_baseline_variants(
            self.baselines_repo,
            machine_type,
        ):
            version = variant["version"]
            firmware_sha384 = variant["firmware_sha384"]
            path = (
                self.artifacts_dir
                / "baselines"
                / machine_type
                / firmware_sha384
                / f"{version}.json"
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            data = (
                json.dumps(variant["baseline"], indent=2) + "\n"
            ).encode()
            path.write_bytes(data)
            baselines.append(PreparedBaseline(
                version=version,
                firmware_sha384=firmware_sha384,
                ref=variant["baseline_ref"],
                path=path,
                sha256=hashlib.sha256(data).hexdigest(),
                firmware_path=self._get_firmware(firmware_sha384),
            ))
        self._baselines[machine_type] = baselines
        return baselines

    def get_podvm(self, podvm_ref: str, podvm_tag: str) -> PodVMArtifact:
        artifact = self._podvms.get(podvm_ref)
        if artifact is not None:
            print(f"  Reusing UKI: {podvm_tag}")
            return artifact

        uki_path = self.artifacts_dir / "uki" / podvm_tag
        print(f"  UKI: {podvm_tag}")
        fetch_uki(podvm_ref, uki_path)
        artifact = PodVMArtifact(
            uki_path=uki_path,
            digest=fetch_oci_digest(podvm_ref),
        )
        self._podvms[podvm_ref] = artifact
        return artifact

    def get_platform_measurements(
        self,
        *,
        target: dict,
        ram_gib: int,
        initdata: bytes,
        podvm_tag: str,
        uki_path: Path,
        baseline: PreparedBaseline,
        output_dir: Path,
    ) -> dict:
        key = (
            target["machine_type"],
            ram_gib,
            podvm_tag,
            baseline.firmware_sha384,
            baseline.sha256,
        )
        measurements = self._platform_measurements.get(key)
        if measurements is not None:
            print(
                f"  Reusing platform measurements for "
                f"{baseline.firmware_sha384[:12]}/{baseline.version}"
            )
            return measurements

        print(
            f"  Computing platform measurements for "
            f"{baseline.firmware_sha384[:12]}/{baseline.version}..."
        )
        computed = compute_measurements(
            ram_gib=ram_gib,
            initdata=initdata,
            firmware_path=baseline.firmware_path,
            baseline_path=baseline.path,
            uki_path=uki_path / "BOOTX64.EFI",
            disk_path=uki_path / "disk.tar.gz",
            output_dir=output_dir,
        )
        measurements = {
            field: value
            for field, value in computed.items()
            if field != "rtmr3"
        }
        self._platform_measurements[key] = measurements
        return measurements


def process_target(
    index: int,
    target: dict,
    machine: dict,
    manifest_file: Path,
    context: GenerationContext,
) -> dict:
    model = target["model"]
    machine_type = target["machine_type"]
    podvm_tag = target["podvm_image_tag"]
    target_dir = context.artifacts_dir / f"target-{index}"

    print(f"\n{'=' * 60}")
    print(f"Target {index}: {model}")
    print(f"{'=' * 60}")

    ram_gib = machine["ram_gib"]
    baselines = context.get_baselines(machine_type)
    podvm_ref = f"{context.podvm_image}:{podvm_tag}"
    podvm = context.get_podvm(podvm_ref, podvm_tag)
    try:
        initdata = resolve_initdata(target, manifest_file)
    except ValueError as error:
        raise ValueError(f"{model}: {error}") from error

    rtmr3 = compute_initdata_rtmr3(initdata)
    measured_variants: list[dict] = []
    for baseline in baselines:
        output_dir = (
            target_dir / baseline.firmware_sha384 / baseline.version
        )
        platform_measurements = context.get_platform_measurements(
            target=target,
            ram_gib=ram_gib,
            initdata=initdata,
            podvm_tag=podvm_tag,
            uki_path=podvm.uki_path,
            baseline=baseline,
            output_dir=output_dir,
        )
        measurements = {
            **platform_measurements,
            "rtmr3": rtmr3,
        }
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "initdata.toml").write_bytes(initdata)
        (output_dir / "measurements.json").write_text(
            json.dumps(measurements, indent=2) + "\n"
        )
        measured_variants.append({
            "version": baseline.version,
            "firmware_sha384": baseline.firmware_sha384,
            "baseline_ref": baseline.ref,
            "baseline_sha256": baseline.sha256,
            "measurements": measurements,
        })

    primary_variant = measured_variants[0]
    target["measurements"] = primary_variant["measurements"]
    target["baseline_variants"] = measured_variants
    return {
        **target,
        **machine,
        "podvm_image": podvm_ref,
        "podvm_digest": podvm.digest,
        "firmware_sha384": primary_variant["firmware_sha384"],
        "baseline_ref": primary_variant["baseline_ref"],
        "baseline_sha256": primary_variant["baseline_sha256"],
        "initdata_hash": target["initdata_sha384"],
    }


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

    doc = yaml.safe_load(manifest_file.read_text()) or {}
    targets = doc.get("targets", [])
    if not targets:
        print("ERROR: no targets in manifest", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(targets)} targets from {manifest_file}")

    machine_types = load_machine_types()
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    context = GenerationContext(
        baselines_repo=baselines_repo,
        podvm_image=podvm_image,
        artifacts_dir=artifacts_dir,
    )
    predicate_targets: list[dict] = []
    for index, target in enumerate(targets):
        try:
            machine = resolve_machine(target, machine_types)
            predicate_targets.append(
                process_target(index, target, machine, manifest_file, context)
            )
        except ValueError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            sys.exit(1)

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
