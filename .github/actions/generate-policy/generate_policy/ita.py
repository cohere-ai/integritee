"""The ITA renderer: Intel TDX targets measured with cvm-measure tdx.

Everything narrower than the shared pipeline lives here: the TDX evidence
filter, the versioned baseline and OVMF firmware fetches that only a TDX
measurement needs, and the Rego this service accepts. ITA enforces a
restricted Rego subset, so prefer constructs the template has already
shipped over ones that merely ought to work.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .fetch import fetch_baseline_variants, fetch_firmware
from .generate import (
    GenerationContext,
    RenderResult,
    ResolvedTarget,
    resolve_nvidia_driver_versions,
)
from .measure import compute_initdata_rtmr3, compute_measurements

TEMPLATE = Path(__file__).parent / "ita-template.rego"

PLATFORM_PLACEHOLDER = "${TDX_PLATFORM_MATCH_BLOCKS}"
WORKLOAD_PLACEHOLDER = "${TDX_WORKLOAD_MATCH_BLOCKS}"
NONCE_PLACEHOLDER = "${POLICY_NONCE}"
DRIVER_VERSIONS_PLACEHOLDER = "${NVIDIA_DRIVER_VERSIONS}"
PLACEHOLDERS = (
    PLATFORM_PLACEHOLDER,
    WORKLOAD_PLACEHOLDER,
    NONCE_PLACEHOLDER,
    DRIVER_VERSIONS_PLACEHOLDER,
)

PLATFORM_FIELDS = ["mrtd", "rtmr0", "rtmr1", "rtmr2"]
MEASUREMENT_RE = re.compile(r"^[0-9a-f]{96,128}$")

# The TEEs ITA can appraise. A target on any other one produces evidence ITA
# cannot read and has no baseline to look up, so it is skipped rather than
# measured.
SUPPORTED_TEES = frozenset({"tdx"})

EMPTY_POLICY_HEADER = """\
# WARNING: this policy matched no TDX target in the manifest. Every generated
# section is empty, so it admits nothing.

"""


def validate_measurement(field: str, value: object) -> str:
    if not isinstance(value, str) or not MEASUREMENT_RE.fullmatch(value):
        raise ValueError(f"invalid or missing TDX measurement: {field}")
    return value


def generate_nonce_rule() -> str:
    nonce = str(uuid.uuid4())
    return f'integritee_nonce := "{nonce}"'


def generate_driver_versions_block(versions: list[str]) -> str:
    """Emit the accepted driver versions as a rule-local set assignment.

    A rule-local set tested by reference is the form with ITA release history;
    a top-level collection and a defaulted function are both constructs ITA
    rejected in the past.
    """
    if not versions:
        return "    accepted_gpu_driver_versions := {}"
    entries = ",\n".join(
        f"        {json.dumps(version)}" for version in versions
    )
    return "\n".join([
        "    accepted_gpu_driver_versions := {",
        entries,
        "    }",
    ])


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
    nv_driver_versions: list[str],
    output_path: Path,
) -> None:
    """Render the Rego policy file from targets with pre-computed measurements.

    An empty target list is a legitimate input, not a failure: it renders an
    inert policy that admits nothing, which is what revoking every target looks
    like. The template's defaults keep that policy loadable.
    """
    template = TEMPLATE.read_text()
    for placeholder in PLACEHOLDERS:
        if placeholder not in template:
            raise ValueError(f"template does not contain {placeholder}")

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
        DRIVER_VERSIONS_PLACEHOLDER,
        generate_driver_versions_block(nv_driver_versions),
    )

    if not variant_count:
        # Warn on inert policy
        print("::warning::ITA policy matched no TDX targets; it admits nothing")
        policy = EMPTY_POLICY_HEADER + policy

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(policy)

    model_names = [target["model"] for target in targets]
    print(
        f"Generated ITA policy with {variant_count} TDX measurement variant(s) "
        f"from {len(targets)} target(s): "
        f"{', '.join(model_names) or 'none'} "
        f"(drivers={', '.join(nv_driver_versions) or 'none'}"
        f") -> {output_path}"
    )


@dataclass(frozen=True)
class PreparedBaseline:
    version: str
    firmware_sha384: str
    ref: str
    path: Path
    sha256: str
    firmware_path: Path


@dataclass
class ItaRenderer:
    """Renders the single Rego policy uploaded to Intel Trust Authority."""

    name = "ita"

    # Run configuration.
    baselines_repo: str
    policy_output: Path

    # Per-run caches. Only a TDX measurement reads these, so they belong to
    # the renderer rather than the shared context.
    _baselines: dict[str, list[PreparedBaseline]] = field(
        default_factory=dict, init=False, repr=False
    )
    _firmware: dict[str, Path] = field(
        default_factory=dict, init=False, repr=False
    )
    _platform_measurements: dict[tuple, dict] = field(
        default_factory=dict, init=False, repr=False
    )

    def cannot_appraise(self, machine: dict) -> str | None:
        if machine["tee"] in SUPPORTED_TEES:
            return None
        supported = ", ".join(sorted(SUPPORTED_TEES))
        return f"ITA appraises {supported} evidence, not {machine['tee']}"

    def render(
        self,
        targets: list[ResolvedTarget],
        context: GenerationContext,
    ) -> RenderResult:
        predicate_targets = {
            resolved.index: self._measure_target(resolved, context)
            for resolved in targets
        }
        manifest_targets = [resolved.target for resolved in targets]
        render_policy(
            manifest_targets,
            resolve_nvidia_driver_versions(
                manifest_targets, context.artifacts_dir
            ),
            self.policy_output,
        )
        return RenderResult(
            policy_files=[self.policy_output],
            predicate_targets=predicate_targets,
        )

    def _get_firmware(
        self,
        firmware_sha384: str,
        context: GenerationContext,
    ) -> Path:
        path = self._firmware.get(firmware_sha384)
        if path is None:
            path = (
                context.artifacts_dir
                / "firmware"
                / f"{firmware_sha384}.fd"
            )
            fetch_firmware(firmware_sha384, path)
            self._firmware[firmware_sha384] = path
        return path

    def _get_baselines(
        self,
        machine_type: str,
        context: GenerationContext,
    ) -> list[PreparedBaseline]:
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
                context.artifacts_dir
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
                firmware_path=self._get_firmware(firmware_sha384, context),
            ))
        self._baselines[machine_type] = baselines
        return baselines

    def _get_platform_measurements(
        self,
        *,
        machine_type: str,
        ram_gib: int,
        initdata: bytes,
        podvm_tag: str,
        uki_path: Path,
        baseline: PreparedBaseline,
        output_dir: Path,
    ) -> dict:
        key = (
            machine_type,
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

    def _measure_target(
        self,
        resolved: ResolvedTarget,
        context: GenerationContext,
    ) -> dict:
        target = resolved.target
        model = target["model"]
        machine_type = target["machine_type"]
        podvm_tag = target["podvm_image_tag"]
        target_dir = context.artifacts_dir / f"target-{resolved.index}"

        print(f"\n{'=' * 60}")
        print(f"Target {resolved.index}: {model}")
        print(f"{'=' * 60}")

        ram_gib = resolved.machine["ram_gib"]
        baselines = self._get_baselines(machine_type, context)
        podvm = context.get_podvm(podvm_tag)
        try:
            initdata = context.get_initdata(target)
        except ValueError as error:
            raise ValueError(f"{model}: {error}") from error

        rtmr3 = compute_initdata_rtmr3(initdata)
        measured_variants: list[dict] = []
        for baseline in baselines:
            output_dir = (
                target_dir / baseline.firmware_sha384 / baseline.version
            )
            platform_measurements = self._get_platform_measurements(
                machine_type=machine_type,
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
            **resolved.machine,
            "podvm_image": podvm.ref,
            "podvm_digest": podvm.digest,
            "firmware_sha384": primary_variant["firmware_sha384"],
            "baseline_ref": primary_variant["baseline_ref"],
            "baseline_sha256": primary_variant["baseline_sha256"],
            "initdata_hash": target["initdata_sha384"],
        }
