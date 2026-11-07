"""The ITA renderer: Intel TDX targets measured with cvm-measure tdx.

Everything narrower than the shared pipeline lives here: the TDX evidence
filter, the versioned baseline and OVMF firmware fetches that only a GCP
measurement needs, and the Rego this service accepts. ITA enforces a
restricted Rego subset, so prefer constructs the template has already
shipped over ones that merely ought to work.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .fetch import fetch_baseline_variants, fetch_firmware
from .generate import (
    GenerationContext,
    RenderResult,
    ResolvedTarget,
    resolve_nvidia_driver_versions,
)
from .measure import compute_initdata_rtmr3, compute_tdx_measurements

TEMPLATE = Path(__file__).parent / "ita-template.rego"
RP_TEMPLATE = Path(__file__).parent / "ita-rp-template.rego"

# The action names its own output. For ITA the name only has to be stable, so
# that the release workflow and prepare-assets have nothing to keep in
# agreement.
POLICY_FILE = "ita_policy.rego"
RP_POLICY_FILE = "ita_rp_policy.rego"

NONCE_PLACEHOLDER = "${POLICY_NONCE}"
RIM_NAMESPACE_PLACEHOLDER = "${RIM_NAMESPACE}"
RTMR3_RIM_NAMES_PLACEHOLDER = "${RTMR3_RIM_NAMES}"
POLICY_ID_PLACEHOLDER = "${POLICY_ID}"
POLICY_HASH_PLACEHOLDER = "${POLICY_HASH}"

# ITA policy IDs are UUIDs; its policy_hash is base64.
POLICY_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
POLICY_HASH_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

# The policy imports <namespace>.rtmr3 and reads only the RIMs it lists under
# it, plus <namespace>.platform.
RIM_NAMESPACE = "public.cohere.v1"
RIM_DIR_NAME = "ita-rims"

# ITA's RIM name rules: dot-separated, <= 128 characters, <= 10 segments,
# each starting with a letter.
RIM_SEGMENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
RIM_NAME_MAX_LENGTH = 128
RIM_NAME_MAX_SEGMENTS = 10

# ITA's CSP RIM catalog currently provides MRTD values only. MRTD is verified
# by the template's mrtd_matches_csp_rim rule; RTMR0 is no longer pinned.
# RTMR1/RTMR2 pairs are accepted through the platform RIM.
PLATFORM_FIELDS = ["rtmr1", "rtmr2"]
MEASUREMENT_RE = re.compile(r"^[0-9a-f]{96,128}$")

# The platforms ITA can appraise with this renderer. Its firmware and baseline
# inputs describe GCP TDX guests specifically, so another platform using TDX
# must not be measured through this path.
SUPPORTED_PLATFORMS = frozenset({("gcp", "tdx")})


def validate_measurement(field: str, value: object) -> str:
    if not isinstance(value, str) or not MEASUREMENT_RE.fullmatch(value):
        raise ValueError(f"invalid or missing TDX measurement: {field}")
    return value


def validate_rim_name(name: str) -> str:
    segments = name.split(".")
    if (
        len(name) > RIM_NAME_MAX_LENGTH
        or len(segments) > RIM_NAME_MAX_SEGMENTS
        or not all(RIM_SEGMENT_RE.fullmatch(part) for part in segments)
    ):
        raise ValueError(f"invalid ITA RIM name: {name!r}")
    return name


def release_rim_namespace(version: str) -> str:
    """The namespace a release's RIMs live under.

    Each release gets its own, so uploading one never overwrites RIMs a live
    policy reads. Without a version (a dry run) the RIMs use the base
    namespace.
    """
    if not version:
        return RIM_NAMESPACE
    segment = re.sub(r"[^A-Za-z0-9_]", "_", version)
    return validate_rim_name(f"{RIM_NAMESPACE}.{segment}")


def generate_rtmr3_rim_names_block(names: Iterable[str]) -> str:
    """Emit the RTMR3 RIMs the policy reads as a rule-local set.

    Listing them bounds the prefix import: a RIM under the prefix that is not
    listed is never read, and a listed name with no RIM matches nothing.
    """
    names = [validate_rim_name(name) for name in names]
    if not names:
        return "    rtmr3_rim_names := {}"
    entries = ",\n".join(f"        {json.dumps(name)}" for name in names)
    return "\n".join(["    rtmr3_rim_names := {", entries, "    }"])


def generate_nonce_rule() -> str:
    nonce = str(uuid.uuid4())
    return f'integritee_nonce := "{nonce}"'


# ITA rejects RIM content over 20 KB (20480 bytes).
RIM_MAX_BYTES = 18 * 1024


def rim_bytes(content: dict) -> bytes:
    """RIM content exactly as uploaded.

    ITA's RIM `hash` is base64 SHA-384 over the bytes it receives. Upload
    sends content through requests, which serializes with `json.dumps`
    defaults, so the release assets use those bytes and match the hash.
    """
    return json.dumps(content).encode()


def _sorted_rtmr3(values: Iterable[str]) -> list[str]:
    return sorted({validate_measurement("rtmr3", value) for value in values})


def pack_rtmr3_rims(
    values: Iterable[str],
    max_bytes: int = RIM_MAX_BYTES,
) -> list[dict]:
    """Pack RTMR3 values into as few RIMs as possible.

    Values are deduplicated and sorted, then each RIM is filled until the next
    value would push it past max_bytes, so the output depends only on the set
    of values.
    """
    rims: list[dict] = []
    current: list[str] = []
    for value in _sorted_rtmr3(values):
        grown = {"rtmr3": [*current, value]}
        if current and len(rim_bytes(grown)) > max_bytes:
            rims.append({"rtmr3": current})
            current = []
        current.append(value)
    if current:
        rims.append({"rtmr3": current})
    return rims


def shard_rtmr3_rims(
    values: Iterable[str],
    shard_count: int,
    max_bytes: int = RIM_MAX_BYTES,
) -> list[dict]:
    """Place each RTMR3 value in shard sha256(value) % shard_count.

    A value's shard never depends on the other values, so adding or removing
    one rewrites only its own shard. Every shard is returned, empty or not.
    """
    shards: list[list[str]] = [[] for _ in range(shard_count)]
    for value in _sorted_rtmr3(values):
        digest = hashlib.sha256(value.encode()).digest()
        shards[int.from_bytes(digest, "big") % shard_count].append(value)
    rims = [{"rtmr3": shard} for shard in shards]
    for index, rim in enumerate(rims):
        if len(rim_bytes(rim)) > max_bytes:
            raise ValueError(f"RTMR3 shard {index} exceeds {max_bytes} bytes")
    return rims


def platform_rim(
    platform_measurements: Iterable[Mapping[str, str]],
    driver_versions: Iterable[str],
    max_bytes: int = RIM_MAX_BYTES,
) -> dict:
    """The platform RIM: accepted RTMR1/RTMR2 pairs and GPU driver versions.

    RTMR1 and RTMR2 are only accepted together, so they stay one entry; driver
    versions are accepted with any pair.
    """
    pairs = sorted({
        tuple(
            validate_measurement(field, measurements.get(field))
            for field in PLATFORM_FIELDS
        )
        for measurements in platform_measurements
    })
    rim = {
        "rtmr1_rtmr2": [dict(zip(PLATFORM_FIELDS, pair)) for pair in pairs],
        "nvidia_driver_versions": sorted(set(driver_versions)),
    }
    if len(rim_bytes(rim)) > max_bytes:
        raise ValueError(f"platform RIM exceeds {max_bytes} bytes")
    return rim


def _render_template(
    template: Path,
    replacements: Mapping[str, str],
    output_path: Path,
) -> None:
    policy = template.read_text()
    for placeholder, value in replacements.items():
        if placeholder not in policy:
            raise ValueError(f"{template.name} does not contain {placeholder}")
        policy = policy.replace(placeholder, value)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(policy)


def _rim_replacements(
    rim_namespace: str,
    rtmr3_rim_names: Iterable[str],
) -> dict[str, str]:
    return {
        RIM_NAMESPACE_PLACEHOLDER: validate_rim_name(rim_namespace),
        RTMR3_RIM_NAMES_PLACEHOLDER: generate_rtmr3_rim_names_block(
            rtmr3_rim_names
        ),
    }


def render_policy(
    rim_namespace: str,
    rtmr3_rim_names: Iterable[str],
    output_path: Path,
    nonce: bool = False,
) -> None:
    """Render the Rego policy reading the named RIMs under rim_namespace.

    rtmr3_rim_names are the last name segments, e.g. "s00". Without nonce the
    policy depends only on its inputs.
    """
    _render_template(
        TEMPLATE,
        {
            **_rim_replacements(rim_namespace, rtmr3_rim_names),
            NONCE_PLACEHOLDER: generate_nonce_rule() if nonce else "",
        },
        output_path,
    )
    print(f"Generated ITA policy reading {rim_namespace} -> {output_path}")


def render_rp_policy(
    rim_dir: Path,
    policy_id: str,
    policy_hash: str,
    output_path: Path,
) -> None:
    """Render the RP policy for the RIMs in rim_dir.

    The namespace comes from the platform RIM, so the RP policy reads the same
    RIMs as the ITA policy rendered with them. policy_id and policy_hash are
    what ITA returned for the uploaded policy, so they are only known after
    the upload. The token's policy_ids_matched entries carry the hash
    base64-encoded once more.
    """
    if not POLICY_ID_RE.fullmatch(policy_id):
        raise ValueError(f"invalid ITA policy ID: {policy_id!r}")
    if not POLICY_HASH_RE.fullmatch(policy_hash):
        raise ValueError(f"invalid ITA policy hash: {policy_hash!r}")
    rim_names = sorted(path.stem for path in rim_dir.glob("*.json"))
    namespaces = [
        name.removesuffix(".platform")
        for name in rim_names
        if name.endswith(".platform")
    ]
    if len(namespaces) != 1:
        raise ValueError(f"expected one platform RIM in {rim_dir}")
    rim_namespace = namespaces[0]
    _render_template(
        RP_TEMPLATE,
        {
            **_rim_replacements(
                rim_namespace, rtmr3_short_names(rim_namespace, rim_names)
            ),
            POLICY_ID_PLACEHOLDER: json.dumps(policy_id),
            POLICY_HASH_PLACEHOLDER: json.dumps(
                base64.b64encode(policy_hash.encode()).decode()
            ),
        },
        output_path,
    )
    print(f"Generated ITA RP policy for {policy_id} -> {output_path}")


def _variant_measurements(target: Mapping) -> list[Mapping[str, str]]:
    """Measurements per baseline variant, or the target's own without any."""
    variants = target.get("baseline_variants")
    if not variants:
        return [target["measurements"]]
    return [variant["measurements"] for variant in variants]


def rtmr3_short_names(
    rim_namespace: str,
    rim_names: Iterable[str],
) -> list[str]:
    """The RTMR3 RIMs among rim_names, without their namespace prefix."""
    prefix = f"{rim_namespace}.rtmr3."
    return [
        name.removeprefix(prefix)
        for name in rim_names
        if name.startswith(prefix)
    ]


def render_rims(
    targets: Iterable[Mapping],
    nv_driver_versions: Iterable[str],
    rim_namespace: str,
    output_dir: Path,
    rtmr3_shards: int | None = None,
) -> list[str]:
    """Write every RIM the policy reads to output_dir/<name>.json.

    Returns the RIM names.

    RTMR3 values are packed tightly unless rtmr3_shards is set, in which case
    they are hash-sharded into that many RIMs.

    An empty target list is a legitimate input, not a failure: RIMs with no
    values admit nothing, which is what revoking every target looks like.
    """
    variants = [
        measurements
        for target in targets
        for measurements in _variant_measurements(target)
    ]
    rtmr3_values = [variant.get("rtmr3") for variant in variants]
    if rtmr3_shards is None:
        rtmr3_rims = pack_rtmr3_rims(rtmr3_values)
    else:
        rtmr3_rims = shard_rtmr3_rims(rtmr3_values, rtmr3_shards)

    rims = {
        validate_rim_name(f"{rim_namespace}.rtmr3.s{index:02d}"): rim
        for index, rim in enumerate(rtmr3_rims)
    }
    rims[validate_rim_name(f"{rim_namespace}.platform")] = platform_rim(
        variants, nv_driver_versions
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, rim in rims.items():
        (output_dir / f"{name}.json").write_bytes(rim_bytes(rim))
    print(f"Generated {len(rims)} ITA RIM(s) -> {output_dir}")
    return list(rims)


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
    """Renders the Rego policy and RIMs uploaded to Intel Trust Authority."""

    name = "ita"

    # Run configuration.
    baselines_repo: str
    output_dir: Path
    version: str = ""
    rtmr3_shards: int | None = None
    nonce: bool = False

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

    @property
    def policy_file(self) -> Path:
        return self.output_dir / POLICY_FILE

    @property
    def rim_namespace(self) -> str:
        return release_rim_namespace(self.version)

    @property
    def rim_dir(self) -> Path:
        return self.output_dir / RIM_DIR_NAME

    @property
    def policy_files(self) -> list[Path]:
        # The RIM count varies per run, so every RIM file present is stale.
        return [
            self.policy_file,
            self.output_dir / RP_POLICY_FILE,
            *sorted(self.rim_dir.glob("*.json")),
        ]

    def cannot_appraise(self, provider: str, machine: dict) -> str | None:
        platform = (provider, machine["tee"])
        if platform in SUPPORTED_PLATFORMS:
            return None
        return (
            "ITA appraises GCP TDX evidence, not "
            f"{provider} {machine['tee']}"
        )

    def render(
        self,
        targets: list[ResolvedTarget],
        context: GenerationContext,
    ) -> RenderResult:
        measured_targets = {
            resolved.index: self._measure_target(resolved, context)
            for resolved in targets
        }
        policy_targets = [
            measured_targets[resolved.index] for resolved in targets
        ]
        if not policy_targets:
            print(
                "::warning::ITA policy matched no TDX targets; "
                "it admits nothing"
            )
        rim_names = render_rims(
            policy_targets,
            resolve_nvidia_driver_versions(
                policy_targets, context.artifacts_dir
            ),
            self.rim_namespace,
            self.rim_dir,
            self.rtmr3_shards,
        )
        render_policy(
            self.rim_namespace,
            rtmr3_short_names(self.rim_namespace, rim_names),
            self.policy_file,
            self.nonce,
        )
        return RenderResult(
            outputs={
                "ita-policy-file": str(self.policy_file),
                "ita-rim-dir": str(self.rim_dir),
            },
            predicate_targets=measured_targets,
            predicate_metadata={"ita_rims": sorted(rim_names)},
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
        computed = compute_tdx_measurements(
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
        return {
            **target,
            "measurements": primary_variant["measurements"],
            "baseline_variants": measured_variants,
            **resolved.machine,
            "podvm_image": podvm.ref,
            "podvm_digest": podvm.digest,
            "firmware_sha384": primary_variant["firmware_sha384"],
            "baseline_ref": primary_variant["baseline_ref"],
            "baseline_sha256": primary_variant["baseline_sha256"],
            "initdata_hash": target["initdata_sha384"],
        }
