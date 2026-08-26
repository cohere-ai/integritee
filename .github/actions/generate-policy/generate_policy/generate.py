"""Shared pipeline behind the generate-policy action.

Reads the manifest, resolves each target's machine type, and hands the
targets to one renderer per attestation service. A renderer owns the three
things the services disagree about -- which evidence it can appraise, how it
measures a target, and the template it fills -- so everything around those
lives here and is done once, including the PodVM pull that dominates runtime.

Returns structured predicate data so the caller can persist it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import yaml

from .fetch import fetch_oci_digest, fetch_uki
from .measure import resolve_initdata

MACHINE_TYPES_PATH = Path(__file__).parent / "machine-types.yaml"

# Where every renderer writes its Rego. The action owns this location rather
# than taking it as an input, so a filename that carries meaning -- Trustee
# resolves {policy_id}_{tee_class}.rego -- cannot be half-defined by a
# caller, and no later step has to guess a path the generator chose.
POLICY_DIR_NAME = "generated-policies"

# The workspace is the base because it is the only mounted directory a Docker
# action can hand files back through.
def policy_output_dir() -> Path:
    return Path(os.environ.get("GITHUB_WORKSPACE", ".")) / POLICY_DIR_NAME


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


def resolve_nvidia_driver_versions(
    targets: list[dict], artifacts_dir: Path
) -> list[str]:
    """Resolve accepted NVIDIA driver versions from UKI measurements.json files.

    Every version comes from a target's own PodVM image, so a manifest spanning
    images that disagree accepts each of them rather than failing generation,
    the same disjunction a multi-target manifest already implies for platform
    and workload blocks.
    """
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

    return sorted(set(versions.values()))


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
class PodVMArtifact:
    ref: str
    uki_path: Path
    digest: str


@dataclass(frozen=True)
class ResolvedTarget:
    """A manifest target paired with the machine facts behind it.

    The index is the target's position in the manifest, which names its
    artifact directory and keys its predicate entry.
    """

    index: int
    target: dict
    machine: dict


@dataclass(frozen=True)
class RenderResult:
    """What one renderer produced.

    Predicate entries are keyed by manifest index rather than listed, so a
    target appraised by more than one service accumulates into a single
    entry instead of appearing once per renderer.
    """

    outputs: dict[str, str]
    predicate_targets: dict[int, dict]


@dataclass
class GenerationContext:
    """Run configuration and the artifacts every renderer shares."""

    # Run configuration.
    manifest_file: Path
    podvm_image: str
    artifacts_dir: Path

    # Per-run caches. Callers use the methods below, not these dictionaries.
    _podvms: dict[str, PodVMArtifact] = field(
        default_factory=dict, init=False, repr=False
    )
    _initdata: dict[str, bytes] = field(
        default_factory=dict, init=False, repr=False
    )

    def get_podvm(self, podvm_tag: str) -> PodVMArtifact:
        """Pull and extract a PodVM image once per tag.

        This is the expensive step of the run and nothing about it is
        service-specific, which is most of the reason the pipeline is shared.
        """
        podvm_ref = f"{self.podvm_image}:{podvm_tag}"
        artifact = self._podvms.get(podvm_ref)
        if artifact is not None:
            print(f"  Reusing UKI: {podvm_tag}")
            return artifact

        uki_path = self.artifacts_dir / "uki" / podvm_tag
        print(f"  UKI: {podvm_tag}")
        fetch_uki(podvm_ref, uki_path)
        artifact = PodVMArtifact(
            ref=podvm_ref,
            uki_path=uki_path,
            digest=fetch_oci_digest(podvm_ref),
        )
        self._podvms[podvm_ref] = artifact
        return artifact

    def get_initdata(self, target: dict) -> bytes:
        """Load and digest-check a target's initdata once.

        Every service measures the same bytes into its own register, so
        resolving them per renderer would risk them disagreeing.
        """
        initdata = self._initdata.get(target.get("initdata_sha384"))
        if initdata is None:
            initdata = resolve_initdata(target, self.manifest_file)
            self._initdata[target["initdata_sha384"]] = initdata
        return initdata


class Renderer(Protocol):
    """One attestation service's view of the manifest."""

    name: str

    @property
    def policy_files(self) -> list[Path]:
        """Every Rego file this renderer writes, known before it runs.

        Declared up front so stale output can be cleared without having to
        run the renderer that would overwrite it.
        """

    def cannot_appraise(self, machine: dict) -> str | None:
        """Why this renderer cannot appraise the machine, or None if it can.

        The reason names the service, since it reaches the log as the
        explanation for a skipped target.
        """

    def render(
        self,
        targets: list[ResolvedTarget],
        context: GenerationContext,
    ) -> RenderResult:
        """Measure the targets and write this service's policy files.

        An empty target list is a legitimate input: it renders an inert
        policy rather than failing, so a caller's success never depends on
        manifest contents it may not control.
        """


def parse_policy_types(raw: str, known: Iterable[str]) -> list[str]:
    """Parse the policy-types input into an ordered, deduplicated list.
    """
    requested = [item for item in re.split(r"[,\s]+", raw.strip()) if item]
    supported = sorted(known)
    if not requested:
        raise ValueError(
            f"policy-types is empty; expected one or more of {supported}"
        )
    unknown = [item for item in requested if item not in supported]
    if unknown:
        raise ValueError(
            f"unknown policy type(s) {unknown}; expected one or more of "
            f"{supported}"
        )
    return list(dict.fromkeys(requested))


def clear_policies(renderers: Iterable[Renderer]) -> None:
    """Remove policies from an earlier run before writing new ones.

    A file left behind by a previous invocation would otherwise be attested
    and released as though it were current, so this covers every type the
    action can emit rather than only the requested ones. It removes only the
    names the action itself writes, since the directory it owns sits inside
    the caller's checkout.
    """
    for renderer in renderers:
        for path in renderer.policy_files:
            if path.exists():
                print(f"Removing stale policy: {path}")
                path.unlink()


def write_outputs(outputs: dict[str, str]) -> None:
    """Report what was written back to the workflow.

    A Docker action cannot give its outputs a value in action.yml, so every
    path a later step needs arrives here rather than as a literal the caller
    has to keep in agreement with this code.
    """
    for name, value in outputs.items():
        print(f"  {name}={value}")

    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    with open(output_file, "a", encoding="utf-8") as handle:
        for name, value in outputs.items():
            handle.write(f"{name}={value}\n")


def load_targets(manifest_file: Path) -> list[dict]:
    if not manifest_file.exists():
        print(f"ERROR: manifest file not found: {manifest_file}", file=sys.stderr)
        sys.exit(1)

    doc = yaml.safe_load(manifest_file.read_text()) or {}
    targets = doc.get("targets", [])
    if not targets:
        print("ERROR: no targets in manifest", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(targets)} targets from {manifest_file}")
    return targets


def generate_policy(
    manifest_file: Path,
    podvm_image: str,
    artifacts_dir: Path,
    renderers: list[Renderer],
    predicate_file: Path | None = None,
) -> None:
    """Run every renderer over the manifest and update the predicate.

    If predicate_file is provided and exists, it is read, updated in place
    with cvm_measure_version and per-target data, and written back.
    """
    targets = load_targets(manifest_file)
    machine_types = load_machine_types()
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    context = GenerationContext(
        manifest_file=manifest_file,
        podvm_image=podvm_image,
        artifacts_dir=artifacts_dir,
    )

    resolved: list[ResolvedTarget] = []
    for index, target in enumerate(targets):
        try:
            machine = resolve_machine(target, machine_types)
        except ValueError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            sys.exit(1)
        resolved.append(ResolvedTarget(index, target, machine))

    predicate_targets: dict[int, dict] = {}
    target_counts: dict[str, int] = {}
    for renderer in renderers:
        selected: list[ResolvedTarget] = []
        for candidate in resolved:
            reason = renderer.cannot_appraise(candidate.machine)
            if reason:
                print(f"::notice::Skipping {candidate.target['model']}: {reason}")
                continue
            selected.append(candidate)

        print(f"\n{'=' * 60}")
        print(f"Generating {renderer.name} policy")
        print(f"{'=' * 60}")
        try:
            result = renderer.render(selected, context)
        except ValueError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            sys.exit(1)
        for index, entry in result.predicate_targets.items():
            predicate_targets.setdefault(index, {}).update(entry)
        target_counts[renderer.name] = len(selected)
        write_outputs({
            **result.outputs,
            f"{renderer.name}-target-count": str(len(selected)),
        })

    # One type matching nothing is legitimate: an empty policy revokes the
    # targets that service used to admit, which is what withdrawing
    # compromised software looks like and is the end state of migrating off
    # a service. Every requested type matching nothing is different in kind,
    # since no policy this run produced can admit anything, and that is a
    # manifest or configuration mistake rather than an intended revocation.
    if not any(target_counts.values()):
        print(
            "ERROR: no manifest target matched any requested policy type "
            f"({', '.join(target_counts)}); every policy generated here "
            "admits nothing",
            file=sys.stderr,
        )
        sys.exit(1)

    if predicate_file:
        predicate = json.loads(predicate_file.read_text()) if predicate_file.exists() else {}
        predicate["cvm_measure_version"] = get_cvm_measure_version()
        # How much each policy covers, so a policy that matched nothing is
        # legible from the signed artifact rather than discovered later from
        # a node failing attestation.
        predicate["target_counts"] = target_counts
        predicate["targets"] = [
            predicate_targets[index] for index in sorted(predicate_targets)
        ]
        predicate_file.write_text(json.dumps(predicate, indent=2) + "\n")
        print(f"Updated predicate: {predicate_file}")
