#!/usr/bin/env python3
"""Derive a policy manifest from a Blobheart ref or local checkout.

Confidential model IDs come from Blobheart's list-models.sh. Each listed
generated directory is rendered with kustomize, and all target data is read
from the single confidential StatefulSet in that rendered output.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import gzip
import hashlib
import io
import os
import re
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

import yaml

BLOBHEART_REPO = "cohere-ai/blobheart"
BLOBHEART_MODELS_DIR = Path("k8s/geofence-models")
LIST_MODELS_SCRIPT = BLOBHEART_MODELS_DIR / "scripts/list-models.sh"
DEFAULT_GENERATED_DIR = "k8s/geofence-models/base/generated"
CC_SUFFIX = "-cc"
MAX_INITDATA_BYTES = 4 * 1024 * 1024

CC_LABEL_KEY = "cohere.com/confidential-compute"
PROVIDER_LABEL_KEY = "cohere.com/provider"
KATA_MACHINE_ANNOTATION = "io.katacontainers.config.hypervisor.machine_type"
KATA_IMAGE_ANNOTATION = "io.katacontainers.config.hypervisor.image"
KATA_INITDATA_ANNOTATION = "io.katacontainers.config.hypervisor.cc_init_data"
AZURE_PROVIDER = "azure"
# Azure gallery IDs place the image definition after this segment.
AZURE_GALLERY_IMAGES_SEGMENT = "images"
SUPPORTED_PROVIDER_RUNTIMES = {
    "gcp": "kata-remote",
    AZURE_PROVIDER: "kata-remote-azure",
}
INITDATA_DIR = "initdata"

# The table lives in the generate-policy package so it is baked into that
# action's Docker image. This action is composite and gets the whole repo.
MACHINE_TYPES_PATH = (
    Path(__file__).resolve().parents[1]
    / "generate-policy/generate_policy/machine-types.yaml"
)


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Run a command and return stdout, raising with command context."""
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise RuntimeError(f"failed to execute {' '.join(command)}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    return result.stdout


def git_auth_environment() -> dict[str, str]:
    """Authenticate git through gh without changing persistent git config."""
    env = os.environ.copy()
    try:
        config_index = int(env.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        config_index = 0
    env["GIT_CONFIG_COUNT"] = str(config_index + 1)
    env[f"GIT_CONFIG_KEY_{config_index}"] = (
        "credential.https://github.com.helper"
    )
    env[f"GIT_CONFIG_VALUE_{config_index}"] = "!gh auth git-credential"
    return env


def checkout_remote_ref(ref: str, destination: Path) -> Path:
    """Sparse-check out Blobheart's model tree at exactly ref."""
    run_command(
        [
            "gh",
            "repo",
            "clone",
            BLOBHEART_REPO,
            str(destination),
            "--",
            "--filter=blob:none",
            "--no-checkout",
        ]
    )
    git_prefix = ["git", "-C", str(destination)]
    git_env = git_auth_environment()
    run_command(
        git_prefix + ["sparse-checkout", "set", str(BLOBHEART_MODELS_DIR)],
        env=git_env,
    )
    run_command(
        git_prefix + ["fetch", "--depth=1", "origin", ref],
        env=git_env,
    )
    run_command(git_prefix + ["checkout", "--detach", ref], env=git_env)
    checked_out_ref = run_command(
        git_prefix + ["rev-parse", "HEAD"],
        env=git_env,
    ).strip()
    if checked_out_ref != ref:
        raise RuntimeError(
            f"Blobheart checkout resolved to {checked_out_ref or '<empty>'}, "
            f"expected {ref}"
        )
    return destination


def parse_model_list(output: str) -> list[str]:
    """Validate confidential model IDs printed by list-models.sh."""
    models: list[str] = []
    seen: set[str] = set()
    for raw_line in output.splitlines():
        model_id = raw_line.strip()
        if not model_id:
            continue
        if raw_line != model_id or not re.fullmatch(
            r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", model_id
        ):
            raise ValueError(
                f"invalid model ID from {LIST_MODELS_SCRIPT}: {raw_line!r}"
            )
        if not model_id.endswith(CC_SUFFIX):
            raise ValueError(
                f"confidential model ID from {LIST_MODELS_SCRIPT} must end "
                f"in {CC_SUFFIX!r}: {model_id!r}"
            )
        if model_id in seen:
            raise ValueError(
                f"duplicate model ID from {LIST_MODELS_SCRIPT}: {model_id}"
            )
        seen.add(model_id)
        models.append(model_id)
    return models


def list_confidential_models(root: Path) -> list[str]:
    """Return only the models selected by Blobheart's confidential filter."""
    output = run_command(
        [str(root / LIST_MODELS_SCRIPT), "--confidential"],
        cwd=root / BLOBHEART_MODELS_DIR,
    )
    return parse_model_list(output)


def decode_initdata(value: str) -> bytes:
    """Decode and decompress a cc_init_data annotation."""
    try:
        decoded = base64.b64decode(value, validate=True)
        if decoded[:2] == b"\x1f\x8b":
            with gzip.GzipFile(fileobj=io.BytesIO(decoded)) as stream:
                decoded = stream.read(MAX_INITDATA_BYTES + 1)
    except (binascii.Error, gzip.BadGzipFile, EOFError, zlib.error) as error:
        raise ValueError(f"invalid cc_init_data: {error}") from error
    if len(decoded) > MAX_INITDATA_BYTES:
        raise ValueError(
            f"decoded cc_init_data exceeds {MAX_INITDATA_BYTES} bytes"
        )
    return decoded


def write_initdata(value: str, output_dir: Path) -> tuple[str, str]:
    """Write decoded initdata by SHA-384 and return its metadata."""
    decoded = decode_initdata(value)
    digest = hashlib.sha384(decoded).hexdigest()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{digest}.toml"
    if output_path.exists() and output_path.read_bytes() != decoded:
        raise ValueError(f"initdata digest collision: {digest}")
    output_path.write_bytes(decoded)
    return f"{INITDATA_DIR}/{output_path.name}", digest


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _required_text(
    model_id: str,
    values: dict,
    key: str,
    field_path: str,
) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"model '{model_id}': missing or invalid field '{field_path}'")
    return value


def _is_true(value: object) -> bool:
    return value is True or (
        isinstance(value, str) and value.lower() == "true"
    )


def extract_target_fields(
    model_id: str,
    built_yaml: str,
    machine_types: dict[str, dict],
) -> dict[str, str]:
    """Extract and validate one target from rendered multi-document YAML."""
    try:
        documents = list(yaml.safe_load_all(built_yaml))
    except yaml.YAMLError as error:
        raise ValueError(f"model '{model_id}': invalid kustomize build YAML: {error}") from error

    workloads: list[dict] = []
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") != "StatefulSet":
            continue
        metadata = _mapping(document.get("metadata"))
        labels = _mapping(metadata.get("labels"))
        if _is_true(labels.get(CC_LABEL_KEY)):
            workloads.append(document)

    if len(workloads) != 1:
        raise ValueError(
            f"model '{model_id}': expected exactly one StatefulSet with field "
            f"'metadata.labels[{CC_LABEL_KEY}]' true, found {len(workloads)}"
        )

    workload = workloads[0]
    metadata = _mapping(workload.get("metadata"))
    labels = _mapping(metadata.get("labels"))
    provider = _required_text(
        model_id,
        labels,
        PROVIDER_LABEL_KEY,
        f"metadata.labels[{PROVIDER_LABEL_KEY}]",
    )

    spec = _mapping(workload.get("spec"))
    template = _mapping(spec.get("template"))
    template_metadata = _mapping(template.get("metadata"))
    annotations = _mapping(template_metadata.get("annotations"))
    template_spec = _mapping(template.get("spec"))
    machine_type = _required_text(
        model_id,
        annotations,
        KATA_MACHINE_ANNOTATION,
        f"spec.template.metadata.annotations[{KATA_MACHINE_ANNOTATION}]",
    )
    image = _required_text(
        model_id,
        annotations,
        KATA_IMAGE_ANNOTATION,
        f"spec.template.metadata.annotations[{KATA_IMAGE_ANNOTATION}]",
    )
    initdata = _required_text(
        model_id,
        annotations,
        KATA_INITDATA_ANNOTATION,
        f"spec.template.metadata.annotations[{KATA_INITDATA_ANNOTATION}]",
    )
    runtime_class = _required_text(
        model_id,
        template_spec,
        "runtimeClassName",
        "spec.template.spec.runtimeClassName",
    )

    expected_runtime = SUPPORTED_PROVIDER_RUNTIMES.get(provider)
    if expected_runtime is None:
        raise ValueError(
            f"model '{model_id}': unsupported field "
            f"'metadata.labels[{PROVIDER_LABEL_KEY}]' value '{provider}'"
        )
    if runtime_class != expected_runtime:
        raise ValueError(
            f"model '{model_id}': field 'spec.template.spec.runtimeClassName' "
            f"is '{runtime_class}' for provider '{provider}', expected "
            f"'{expected_runtime}'"
        )

    machine_info = machine_types.get(machine_type)
    if not isinstance(machine_info, dict):
        raise ValueError(
            f"model '{model_id}': field "
            f"'spec.template.metadata.annotations[{KATA_MACHINE_ANNOTATION}]' "
            f"has unknown machine type '{machine_type}'"
        )
    machine_platform = machine_info.get("platform")
    if machine_platform != provider:
        raise ValueError(
            f"model '{model_id}': machine type '{machine_type}' platform "
            f"'{machine_platform}' does not match field "
            f"'metadata.labels[{PROVIDER_LABEL_KEY}]' value '{provider}'"
        )

    podvm_image_tag = _podvm_image_tag(model_id, provider, image)
    return {
        "machine_type": machine_type,
        "podvm_image_tag": podvm_image_tag,
        "initdata": initdata,
    }


def _podvm_image_tag(model_id: str, provider: str, image: str) -> str:
    """Resolve the OCI tag of the PodVM artifact a cloud image was built from.

    One OCI artifact is published per PodVM build, tagged with its image name,
    and both providers boot a copy of that artifact. Their image references
    disagree on where the name sits:

      gcp:   projects/<project>/global/images/<name>
      azure: /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute
             /galleries/<gallery>/images/<definition>/versions/<version>

    A GCP reference ends in the name. An Azure gallery ID ends in the immutable
    version and carries the name mid-path as the image definition, which the
    publisher keys on the artifact's image_name. Reading the trailing segment
    for both resolves GCP and fails to resolve Azure, so read the definition
    segment for Azure.
    """
    field = (
        f"model '{model_id}': field "
        f"'spec.template.metadata.annotations[{KATA_IMAGE_ANNOTATION}]'"
    )
    segments = [segment for segment in image.split("/") if segment]

    if provider == AZURE_PROVIDER:
        if AZURE_GALLERY_IMAGES_SEGMENT not in segments:
            raise ValueError(
                f"{field} is not an Azure gallery image ID: no "
                f"'{AZURE_GALLERY_IMAGES_SEGMENT}' segment in '{image}'"
            )
        definition_index = (
            len(segments) - segments[::-1].index(AZURE_GALLERY_IMAGES_SEGMENT)
        )
        if definition_index >= len(segments):
            raise ValueError(
                f"{field} has no image definition after "
                f"'{AZURE_GALLERY_IMAGES_SEGMENT}' in '{image}'"
            )
        return segments[definition_index]

    if not segments:
        raise ValueError(f"{field} has no final path segment")
    return segments[-1]


def load_machine_types() -> dict[str, dict]:
    """Load the shared machine type table."""
    return yaml.safe_load(MACHINE_TYPES_PATH.read_text())


def resolve_local_ref(root: Path) -> str:
    """Return the immutable commit SHA for a local Blobheart checkout."""
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    ref = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", ref):
        detail = result.stderr.strip() or "HEAD did not resolve to a commit SHA"
        raise ValueError(f"cannot resolve Blobheart checkout commit: {detail}")
    return ref


def _generated_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"--generated-dir must be Blobheart-relative: {value}")
    return path


def derive_manifest(
    root: Path,
    ref: str,
    generated_dir: str,
    output_path: Path,
    initdata_dir: Path,
) -> None:
    """Derive and write a manifest from an already checked-out source."""
    generated_path = _generated_path(generated_dir)
    machine_types = load_machine_types()
    model_ids = list_confidential_models(root)
    print(f"Found {len(model_ids)} CC models")

    targets: list[dict] = []
    for model_id in model_ids:
        model_path = generated_path / model_id
        model_dir = root / model_path
        if not model_dir.is_dir():
            raise ValueError(
                f"model '{model_id}': generated directory does not exist: "
                f"{model_path}"
            )

        try:
            built_yaml = run_command(
                ["kustomize", "build", str(model_path)],
                cwd=root,
            )
        except RuntimeError as error:
            raise RuntimeError(f"model '{model_id}': {error}") from error
        fields = extract_target_fields(model_id, built_yaml, machine_types)
        try:
            initdata_file, initdata_sha384 = write_initdata(
                fields["initdata"], initdata_dir
            )
        except ValueError as error:
            raise ValueError(
                f"model '{model_id}': field "
                f"'spec.template.metadata.annotations[{KATA_INITDATA_ANNOTATION}]': "
                f"{error}"
            ) from error

        target = {
            "model": model_id.removesuffix(CC_SUFFIX),
            "machine_type": fields["machine_type"],
            "podvm_image_tag": fields["podvm_image_tag"],
            "initdata_file": initdata_file,
            "initdata_sha384": initdata_sha384,
            "added": datetime.date.today().isoformat(),
            "sources": [ref],
        }
        targets.append(target)
        print(f"Derived {len(targets)} of {len(model_ids)} CC targets")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        yaml.dump({"targets": targets}, default_flow_style=False, sort_keys=False)
    )
    print(f"Derived {len(targets)} targets -> {output_path}")


def main() -> None:
    """Derive a policy manifest from local or remote Blobheart."""
    parser = argparse.ArgumentParser(
        description="Derive manifest from blobheart ref or local checkout"
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--blobheart-ref", help="Blobheart commit SHA")
    source_group.add_argument("--blobheart-dir", help="Path to local blobheart checkout")
    parser.add_argument("--output", required=True, help="Output manifest YAML path")
    parser.add_argument(
        "--initdata-dir",
        type=Path,
        help="Directory for decoded initdata (default: <output-dir>/initdata)",
    )
    parser.add_argument(
        "--generated-dir",
        default=DEFAULT_GENERATED_DIR,
        help=(
            "Blobheart-relative directory holding per-model generated dirs "
            f"(default: {DEFAULT_GENERATED_DIR})"
        ),
    )
    parser.add_argument(
        "--kustomization-path",
        default=None,
        help="Deprecated compatibility argument; accepted but ignored",
    )
    args = parser.parse_args()

    ref = args.blobheart_ref
    if ref and not re.fullmatch(r"[0-9a-f]{40}", ref):
        parser.error("--blobheart-ref must be a 40-character lowercase SHA")
    if args.kustomization_path:
        print(
            "WARNING: --kustomization-path is deprecated and ignored",
            file=sys.stderr,
        )

    output_path = Path(args.output)
    initdata_dir = args.initdata_dir or output_path.parent / INITDATA_DIR
    try:
        if args.blobheart_dir:
            root = Path(args.blobheart_dir).resolve()
            if not root.is_dir():
                parser.error(f"--blobheart-dir is not a directory: {root}")
            try:
                ref = resolve_local_ref(root)
            except ValueError as error:
                parser.error(str(error))
            print(f"Deriving manifest from local://{root}@{ref}")
            derive_manifest(
                root,
                ref,
                args.generated_dir,
                output_path,
                initdata_dir,
            )
        else:
            with tempfile.TemporaryDirectory(prefix="blobheart-") as temp_dir:
                root = checkout_remote_ref(ref, Path(temp_dir) / "blobheart")
                print(f"Deriving manifest from blobheart://{ref}")
                derive_manifest(
                    root,
                    ref,
                    args.generated_dir,
                    output_path,
                    initdata_dir,
                )
    except (RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
