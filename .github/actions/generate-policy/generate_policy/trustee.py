"""The Trustee renderer: Azure SEV-SNP targets measured with cvm-measure.

Emits the pair of Rego files that Trustee's attestation service loads, one
per TEE class. Nothing is uploaded anywhere: these ship as release assets
covered by the same Sigstore attestation as the ITA policy.

Unlike ITA, which appraises one evidence shape, Trustee routes evidence to a
verifier per attester and each verifier's claims land under its own input
key. So the CPU policy is sectioned by attester and a target's (platform,
tee) pair decides which section its reference values go in. Only az-snp-vtpm
has a section today; adding one means a row in ATTESTERS, a placeholder pair
in the template, and a block builder here.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .generate import (
    GenerationContext,
    RenderResult,
    ResolvedTarget,
    resolve_nvidia_driver_versions,
)
from .measure import compute_azure_snp_pcrs

CPU_TEMPLATE = Path(__file__).parent / "trustee-cpu-template.rego"
GPU_TEMPLATE = Path(__file__).parent / "trustee-gpu-template.rego"

# Trustee resolves a policy as {dir}/{policy_id}_{tee_class}.rego, so the
# prefix is half of a contract whose other half is the policy id a deployment
# is configured with. It is a constant rather than an action input for that
# reason: a caller-chosen value would only invite the two to drift.
POLICY_ID = "trustee_policy"
CPU_POLICY_FILE = f"{POLICY_ID}_cpu.rego"
GPU_POLICY_FILE = f"{POLICY_ID}_gpu.rego"

# Which Trustee verifier produced a target's evidence, and so which input key
# and template section its reference values belong to. This routes on claim
# shape rather than measurement values, so it cannot be guessed from the
# platform pair: (azure, tdx) would take az-tdx-vtpm rather than tdx, because
# a vTPM platform emits PCRs alongside the TD quote. Adding a platform means
# confirming which verifier upstream routes its evidence to.
ATTESTERS = {
    ("azure", "snp"): "az-snp-vtpm",
}

AZSNP = "az-snp-vtpm"

# Microsoft's paravisor launch measurements, base64 of 48 bytes. A set so a
# firmware roll can be ridden out by adding the new value beside the old.
#
# Defined here rather than in the template because the release predicate
# records the same values, and writing them twice is how the signed artifact
# comes to disagree with the policy it describes.
AZSNP_PARAVISOR_MEASUREMENTS = (
    "qnydpVwThuWxZTsSWXi+2ns/laha6w+d2723g84FaijJ0CHaI5w0pYw6ZXZUJw7v",
)

AZSNP_MIN_TCB = {
    "bootloader": 10,
    "tee": 0,
    "snp": 27,
    "microcode": 88,
}

# Which registers make up an image's identity, and what az-snp-vtpm calls each
# one. Mapped explicitly because getting it wrong yields a policy that compiles
# and silently never matches.
#
# The zero padding is Trustee's claim spelling rather than a TPM convention, so
# it is translated here instead of upstream: cvm-measure names its output after
# the hardware, as it does with mrtd and rtmr0 on the TDX side.
IMAGE_PCRS = {
    "pcr4": "pcr04",
    "pcr5": "pcr05",
    "pcr9": "pcr09",
    "pcr11": "pcr11",
}
INITDATA_PCR = "pcr8"

PARAVISOR_PLACEHOLDER = "${AZSNP_PARAVISOR_MEASUREMENTS}"
MIN_TCB_PLACEHOLDER = "${AZSNP_MIN_TCB}"
IMAGE_PLACEHOLDER = "${AZSNP_IMAGE_BLOCKS}"
INITDATA_PLACEHOLDER = "${AZSNP_INITDATA_BLOCKS}"
CPU_PLACEHOLDERS = (
    PARAVISOR_PLACEHOLDER,
    MIN_TCB_PLACEHOLDER,
    IMAGE_PLACEHOLDER,
    INITDATA_PLACEHOLDER,
)

DRIVER_VERSIONS_PLACEHOLDER = "${NVIDIA_DRIVER_VERSIONS}"
GPU_PLACEHOLDERS = (DRIVER_VERSIONS_PLACEHOLDER,)

# Azure vTPM PCRs are SHA-256, so 64 hex characters. Never confuse these with
# the SNP report's launch measurement, which is base64 of 48 bytes: SEV-SNP
# has no PCRs.
PCR_RE = re.compile(r"^[0-9a-f]{64}$")
LAUNCH_MEASUREMENT_RE = re.compile(r"^[A-Za-z0-9+/]{64}$")

def empty_policy_header(covered: str) -> str:
    """Say so in the file itself, since an inert policy is easy to miss."""
    return (
        f"# WARNING: this policy pins no {covered}, because no manifest target\n"
        "# reached it. Every generated section is empty, so it admits nothing.\n"
        "\n"
    )


def validate_pcr_hex(field_name: str, value: object) -> str:
    if not isinstance(value, str) or not PCR_RE.fullmatch(value):
        raise ValueError(f"invalid or missing Azure vTPM PCR: {field_name}")
    return value


def validate_snp_launch_measurement(value: object) -> str:
    """Check a base64-encoded 48-byte SNP launch measurement.

    48 bytes encode to 64 base64 characters with no padding, so a value of any
    other length is not a launch measurement whatever else it may be.
    """
    if not isinstance(value, str) or not LAUNCH_MEASUREMENT_RE.fullmatch(value):
        raise ValueError(f"invalid SNP launch measurement: {value!r}")
    return value


def generate_paravisor_block() -> str:
    """Emit the accepted launch measurements, one per line.

    Every multi-value set in these templates is emitted a line at a time:
    regorus caps a line at 1024 columns, and an inline literal that passes at
    four entries breaches that at roughly fifteen.
    """
    return "\n".join(
        f"\t{json.dumps(validate_snp_launch_measurement(measurement))},"
        for measurement in AZSNP_PARAVISOR_MEASUREMENTS
    )


def generate_min_tcb_block() -> str:
    return "\n".join(
        f"\t{json.dumps(component)}: {int(floor)},"
        for component, floor in AZSNP_MIN_TCB.items()
    )


def generate_driver_versions_block(versions: list[str]) -> str:
    return "\n".join(f"\t{json.dumps(version)}," for version in versions)


def generate_image_block(podvm_tag: str, pcrs: dict) -> str:
    """Emit one image's four registers as a single conjunctive rule.

    Fused rather than split per register because all four are measured from
    one disk.raw. Separate rules would each be satisfiable independently, with
    nothing recording which definition satisfied which, so they would admit
    one image's UKI beside another's partition table: a disk that has never
    existed.
    """
    lines = [f"# PodVM image: {podvm_tag}", "azsnp_image_ok if {"]
    for source, claim in IMAGE_PCRS.items():
        value = validate_pcr_hex(source, pcrs.get(source))
        lines.append(f"\tazsnp.tpm.{claim} == {json.dumps(value)}")
    lines.append("}")
    return "\n".join(lines)


def generate_initdata_block(model: str, initdata_label: str, pcr8: str) -> str:
    pcr8 = validate_pcr_hex(INITDATA_PCR, pcr8)
    return "\n".join([
        f"# Model: {model} (Initdata: {initdata_label})",
        "azsnp_initdata_ok if {",
        f"\tinput.init_data == {json.dumps(pcr8)}",
        "}",
    ])


def render_cpu_policy(
    image_blocks: list[str],
    initdata_blocks: list[str],
    output_path: Path,
) -> None:
    """Render the CPU policy, which is mandatory for every appraised peer."""
    policy = _substitute(CPU_TEMPLATE, CPU_PLACEHOLDERS, {
        PARAVISOR_PLACEHOLDER: generate_paravisor_block(),
        MIN_TCB_PLACEHOLDER: generate_min_tcb_block(),
        IMAGE_PLACEHOLDER: "\n\n".join(image_blocks),
        INITDATA_PLACEHOLDER: "\n\n".join(initdata_blocks),
    })

    if not image_blocks:
        print(
            "::warning::Trustee CPU policy matched no Azure SEV-SNP targets; "
            "it admits nothing"
        )
        policy = empty_policy_header("pod VM image") + policy

    _write(output_path, policy)
    print(
        f"Generated Trustee CPU policy with {len(image_blocks)} image block(s) "
        f"and {len(initdata_blocks)} initdata block(s) -> {output_path}"
    )


def render_gpu_policy(versions: list[str], output_path: Path) -> None:
    """Render the GPU policy, which is consulted per TEE class.

    Rendered whether or not any target has a GPU: Trustee treats a missing
    non-CPU policy as acceptable, so omitting the file would quietly stop the
    GPU being appraised rather than fail.
    """
    policy = _substitute(GPU_TEMPLATE, GPU_PLACEHOLDERS, {
        DRIVER_VERSIONS_PLACEHOLDER: generate_driver_versions_block(versions),
    })

    if not versions:
        print(
            "::warning::Trustee GPU policy accepts no driver version; "
            "it admits nothing"
        )
        policy = empty_policy_header("NVIDIA driver version") + policy

    _write(output_path, policy)
    print(
        f"Generated Trustee GPU policy "
        f"(drivers={', '.join(versions) or 'none'}) -> {output_path}"
    )


def _substitute(
    template_path: Path,
    placeholders: tuple[str, ...],
    values: dict[str, str],
) -> str:
    template = template_path.read_text()
    for placeholder in placeholders:
        if placeholder not in template:
            raise ValueError(
                f"{template_path.name} does not contain {placeholder}"
            )
        template = template.replace(placeholder, values[placeholder])
    return template


def _write(output_path: Path, policy: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(policy)


@dataclass
class TrusteeRenderer:
    """Renders the Rego policy pair a Trustee attestation service loads."""

    name = "trustee"

    # Run configuration.
    output_dir: Path

    # Per-run cache. The registers are a function of the image and the
    # initdata, so two targets sharing both measure once.
    _pcrs: dict[tuple, dict] = field(
        default_factory=dict, init=False, repr=False
    )

    @property
    def cpu_policy_file(self) -> Path:
        return self.output_dir / CPU_POLICY_FILE

    @property
    def gpu_policy_file(self) -> Path:
        return self.output_dir / GPU_POLICY_FILE

    @property
    def policy_files(self) -> list[Path]:
        return [self.cpu_policy_file, self.gpu_policy_file]

    def cannot_appraise(self, machine: dict) -> str | None:
        if (machine["platform"], machine["tee"]) in ATTESTERS:
            return None
        return (
            f"no Trustee section for ({machine['platform']}, {machine['tee']})"
        )

    def render(
        self,
        targets: list[ResolvedTarget],
        context: GenerationContext,
    ) -> RenderResult:
        image_blocks: list[str] = []
        initdata_blocks: list[str] = []
        seen_images: set[str] = set()
        seen_initdata: set[str] = set()
        predicate_targets: dict[int, dict] = {}

        for resolved in targets:
            attester = ATTESTERS[
                (resolved.machine["platform"], resolved.machine["tee"])
            ]
            # One attester has a section today, and a target reaching here
            # already resolved to one, so anything else is a section that was
            # mapped without being written.
            if attester != AZSNP:
                raise ValueError(f"no block builder for attester {attester}")

            pcrs, entry = self._measure_target(resolved, context)
            predicate_targets[resolved.index] = entry

            podvm_tag = resolved.target["podvm_image_tag"]
            if podvm_tag not in seen_images:
                seen_images.add(podvm_tag)
                image_blocks.append(generate_image_block(podvm_tag, pcrs))

            pcr8 = pcrs.get(INITDATA_PCR)
            if pcr8 not in seen_initdata:
                seen_initdata.add(pcr8)
                initdata_blocks.append(generate_initdata_block(
                    resolved.target["model"],
                    resolved.target.get("initdata_sha384", "unknown")[:12],
                    pcr8,
                ))

        render_cpu_policy(image_blocks, initdata_blocks, self.cpu_policy_file)
        render_gpu_policy(
            resolve_nvidia_driver_versions(
                [resolved.target for resolved in targets],
                context.artifacts_dir,
            ),
            self.gpu_policy_file,
        )

        return RenderResult(
            outputs={
                "trustee-cpu-policy-file": str(self.cpu_policy_file),
                "trustee-gpu-policy-file": str(self.gpu_policy_file),
                # How a consumer learns which directory to configure. Sharing
                # it with the ITA policy is safe, since Trustee builds exact
                # paths from the policy id and tee class and never reads a file
                # carrying another prefix.
                "trustee-policy-dir": str(self.output_dir),
            },
            predicate_targets=predicate_targets,
            predicate_metadata={"trustee_policies": self._describe_policies()},
        )

    def _describe_policies(self) -> dict:
        """What the signed predicate records about this pair of policies.

        The reference values a reader cannot recover from a target entry,
        because they are properties of the platform rather than of anything
        we build, plus a digest per file so the predicate says which released
        asset it is describing.
        """
        return {
            "policy_id": POLICY_ID,
            "files": {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.policy_files
            },
            "azure_snp": {
                "paravisor_measurements": list(AZSNP_PARAVISOR_MEASUREMENTS),
                "min_tcb": dict(AZSNP_MIN_TCB),
            },
        }

    def _measure_target(
        self,
        resolved: ResolvedTarget,
        context: GenerationContext,
    ) -> tuple[dict, dict]:
        target = resolved.target
        model = target["model"]
        podvm_tag = target["podvm_image_tag"]

        print(f"\n{'=' * 60}")
        print(f"Target {resolved.index}: {model}")
        print(f"{'=' * 60}")

        podvm = context.get_podvm(podvm_tag)
        try:
            initdata = context.get_initdata(target)
        except ValueError as error:
            raise ValueError(f"{model}: {error}") from error

        key = (podvm_tag, target["initdata_sha384"])
        pcrs = self._pcrs.get(key)
        if pcrs is None:
            output_dir = (
                context.artifacts_dir
                / f"target-{resolved.index}"
                / "azure-snp"
            )
            pcrs = compute_azure_snp_pcrs(
                initdata=initdata,
                uki_path=podvm.uki_path / "BOOTX64.EFI",
                disk_path=podvm.uki_path / "disk.tar.gz",
                output_dir=output_dir,
            )
            self._pcrs[key] = pcrs
        else:
            print(f"  Reusing Azure SNP PCRs for {podvm_tag}")

        return pcrs, {
            **target,
            **resolved.machine,
            "podvm_image": podvm.ref,
            "podvm_digest": podvm.digest,
            "initdata_hash": target["initdata_sha384"],
            "azure_snp": pcrs,
        }
