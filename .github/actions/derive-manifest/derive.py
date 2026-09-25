#!/usr/bin/env python3
"""Derive a policy manifest from a Blobheart ref or local checkout.

Confidential model IDs come from Blobheart's declarative model catalog. Each
listed generated directory is rendered with kustomize, and all target data is
read from the single confidential StatefulSet in that rendered output.
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

GENERATE_POLICY_ACTION = (
    Path(__file__).resolve().parents[1] / "generate-policy"
)
sys.path.insert(0, str(GENERATE_POLICY_ACTION))

from generate_policy.manifest_contract import (  # noqa: E402
    PROVIDER_RUNTIMES,
    SCHEMA_VERSION,
    load_machine_types,
    target_provider,
)

BLOBHEART_REPO = "cohere-ai/blobheart"
BLOBHEART_MODELS_DIR = Path("k8s/geofence-models")
MODEL_CATALOG = BLOBHEART_MODELS_DIR / "base/models.yaml"
DEFAULT_GENERATED_DIR = "k8s/geofence-models/base/generated"
# Naming contract: a catalog model is confidential if and only if its ID ends
# in CC_SUFFIX. Models without the suffix are never rendered, so a confidential
# workload under a non-suffixed ID gets no policy target and fails closed at
# attestation rather than here.
CC_SUFFIX = "-cc"
MAX_INITDATA_BYTES = 4 * 1024 * 1024
INITDATA_DIR = "initdata"
WORKLOAD_KIND = "StatefulSet"
RENDERED_PATHS = {
    "workload_name": ("metadata", "name"),
    "confidential_compute": (
        "metadata",
        "labels",
        "cohere.com/confidential-compute",
    ),
    "provider": ("metadata", "labels", "cohere.com/provider"),
    "machine_type": (
        "spec",
        "template",
        "metadata",
        "annotations",
        "io.katacontainers.config.hypervisor.machine_type",
    ),
    "podvm_image": (
        "spec",
        "template",
        "metadata",
        "annotations",
        "io.katacontainers.config.hypervisor.image",
    ),
    "initdata": (
        "spec",
        "template",
        "metadata",
        "annotations",
        "io.katacontainers.config.hypervisor.cc_init_data",
    ),
    "runtime_class": ("spec", "template", "spec", "runtimeClassName"),
}


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
    # Fetch only the requested commit's trees; a `clone` would first pull
    # every commit and tree in Blobheart's history before the shallow fetch.
    destination.mkdir(parents=True, exist_ok=True)
    git_prefix = ["git", "-C", str(destination)]
    git_env = git_auth_environment()
    run_command(git_prefix + ["init", "--quiet"], env=git_env)
    run_command(
        git_prefix
        + ["remote", "add", "origin", f"https://github.com/{BLOBHEART_REPO}.git"],
        env=git_env,
    )
    run_command(
        git_prefix + ["sparse-checkout", "set", str(BLOBHEART_MODELS_DIR)],
        env=git_env,
    )
    run_command(
        git_prefix
        + ["fetch", "--depth=1", "--filter=blob:none", "origin", ref],
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


def parse_model_catalog(document: object) -> list[str]:
    """Validate the model catalog and return confidential model IDs."""
    if not isinstance(document, dict) or not isinstance(
        document.get("models"), list
    ):
        raise ValueError(
            f"invalid model catalog '{MODEL_CATALOG}': expected models list"
        )

    models: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(document["models"]):
        if not isinstance(entry, dict):
            raise ValueError(
                f"invalid model catalog '{MODEL_CATALOG}': "
                f"models[{index}] must be a mapping"
            )
        model_id = entry.get("id")
        if not isinstance(model_id, str) or not re.fullmatch(
            r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", model_id
        ):
            raise ValueError(
                f"invalid model ID in {MODEL_CATALOG} at models[{index}]: "
                f"{model_id!r}"
            )
        if model_id in seen:
            raise ValueError(
                f"duplicate model ID in {MODEL_CATALOG}: {model_id}"
            )
        seen.add(model_id)
        if model_id.endswith(CC_SUFFIX):
            models.append(model_id)
    return models


def list_confidential_models(root: Path) -> list[str]:
    """Read confidential model IDs without executing Blobheart code."""
    catalog_path = root / MODEL_CATALOG
    if catalog_path.is_symlink():
        raise ValueError(f"model catalog must not be a symlink: {MODEL_CATALOG}")
    try:
        document = yaml.safe_load(catalog_path.read_text())
    except OSError as error:
        raise ValueError(
            f"cannot read model catalog '{MODEL_CATALOG}': {error}"
        ) from error
    except yaml.YAMLError as error:
        raise ValueError(
            f"invalid model catalog '{MODEL_CATALOG}': {error}"
        ) from error
    return parse_model_catalog(document)


def render_environment(home: Path) -> dict[str, str]:
    """Return a minimal environment without checkout credentials."""
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "",
    }


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


def _rendered_value(workload: dict, field_name: str) -> object:
    value: object = workload
    for part in RENDERED_PATHS[field_name]:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _required_rendered_text(model_id: str, workload: dict, field_name: str) -> str:
    value = _rendered_value(workload, field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"model '{model_id}': missing or invalid field "
            f"'{'.'.join(RENDERED_PATHS[field_name])}'"
        )
    return value


def _is_true(value: object) -> bool:
    return value is True or (
        isinstance(value, str) and value.lower() == "true"
    )


def _podvm_image_tag(model_id: str, provider: str, image: str) -> str:
    """Resolve the OCI tag from a GCP image or Azure gallery image ID."""
    segments = [segment for segment in image.split("/") if segment]
    if provider == "azure":
        normalized_segments = [segment.lower() for segment in segments]
        image_segments = [
            index
            for index, segment in enumerate(normalized_segments)
            if segment == "images"
        ]
        index = image_segments[-1] if image_segments else -1
        # .../images/<definition>/versions/<version> with nothing after it.
        if (
            index < 0
            or index + 4 != len(segments)
            or normalized_segments[index + 2] != "versions"
        ):
            raise ValueError(
                f"model '{model_id}': field "
                f"'{'.'.join(RENDERED_PATHS['podvm_image'])}' "
                f"is not an Azure gallery image ID: '{image}'"
            )
        return segments[index + 1]
    # .../images/<name>; rejects e.g. .../images/family/<family>.
    if len(segments) < 2 or segments[-2] != "images":
        raise ValueError(
            f"model '{model_id}': field "
            f"'{'.'.join(RENDERED_PATHS['podvm_image'])}' "
            f"is not a GCP image path ending in images/<name>: '{image}'"
        )
    return segments[-1]


def extract_target_fields(
    model_id: str,
    built_yaml: str,
    machine_types: dict[str, dict],
) -> dict[str, str]:
    """Extract and validate one target from rendered multi-document YAML."""
    try:
        documents = list(yaml.safe_load_all(built_yaml))
    except yaml.YAMLError as error:
        raise ValueError(
            f"model '{model_id}': invalid kustomize build YAML: {error}"
        ) from error

    workloads: list[dict] = []
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") != WORKLOAD_KIND:
            continue
        if _is_true(_rendered_value(document, "confidential_compute")):
            workloads.append(document)

    if len(workloads) != 1:
        raise ValueError(
            f"model '{model_id}': expected exactly one {WORKLOAD_KIND} with "
            f"field '{'.'.join(RENDERED_PATHS['confidential_compute'])}' true, "
            f"found {len(workloads)}"
        )

    workload = workloads[0]
    workload_name = _required_rendered_text(model_id, workload, "workload_name")
    if workload_name != model_id:
        raise ValueError(
            f"model '{model_id}': field "
            f"'{'.'.join(RENDERED_PATHS['workload_name'])}' is "
            f"'{workload_name}', expected '{model_id}'"
        )
    provider = _required_rendered_text(model_id, workload, "provider")
    machine_type = _required_rendered_text(model_id, workload, "machine_type")
    image = _required_rendered_text(model_id, workload, "podvm_image")
    initdata = _required_rendered_text(model_id, workload, "initdata")
    runtime_class = _required_rendered_text(model_id, workload, "runtime_class")

    expected_runtime = PROVIDER_RUNTIMES.get(provider)
    if expected_runtime is None:
        raise ValueError(
            f"model '{model_id}': unsupported field "
            f"'{'.'.join(RENDERED_PATHS['provider'])}' value '{provider}'"
        )
    if runtime_class != expected_runtime:
        raise ValueError(
            f"model '{model_id}': field "
            f"'{'.'.join(RENDERED_PATHS['runtime_class'])}' "
            f"is '{runtime_class}' for provider '{provider}', expected "
            f"'{expected_runtime}'"
        )

    try:
        target_provider(
            {"provider": provider, "machine_type": machine_type},
            machine_types,
            SCHEMA_VERSION,
        )
    except ValueError as error:
        raise ValueError(
            f"model '{model_id}': invalid provider/machine type: {error}"
        ) from error

    return {
        "provider": provider,
        "machine_type": machine_type,
        "podvm_image_tag": _podvm_image_tag(model_id, provider, image),
        "initdata": initdata,
    }


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
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.is_relative_to(BLOBHEART_MODELS_DIR)
    ):
        raise ValueError(
            "--generated-dir must be under "
            f"{BLOBHEART_MODELS_DIR}: {value}"
        )
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
    if (root / generated_path).resolve() != root.resolve() / generated_path:
        raise ValueError(
            f"generated directory must not contain symlinks: {generated_path}"
        )
    machine_types = load_machine_types()
    model_ids = list_confidential_models(root)
    if not model_ids:
        raise ValueError(f"no confidential models found in {MODEL_CATALOG}")
    print(f"Found {len(model_ids)} CC models")

    targets: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="kustomize-home-") as home:
        environment = render_environment(Path(home))
        for model_id in model_ids:
            model_path = generated_path / model_id
            model_dir = root / model_path
            if model_dir.is_symlink() or not model_dir.is_dir():
                raise ValueError(
                    f"model '{model_id}': generated directory does not exist "
                    f"or is a symlink: {model_path}"
                )

            try:
                built_yaml = run_command(
                    ["kustomize", "build", str(model_path)],
                    cwd=root,
                    env=environment,
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
                    f"'{'.'.join(RENDERED_PATHS['initdata'])}': "
                    f"{error}"
                ) from error

            target = {
                "model": model_id.removesuffix(CC_SUFFIX),
                "provider": fields["provider"],
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
        yaml.dump(
            {"schema_version": SCHEMA_VERSION, "targets": targets},
            default_flow_style=False,
            sort_keys=False,
        )
    )
    print(f"Derived {len(targets)} targets -> {output_path}")


def main() -> None:
    """Derive a policy manifest from local or remote Blobheart."""
    parser = argparse.ArgumentParser(
        description="Derive manifest from blobheart ref or local checkout"
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--blobheart-ref", help="Blobheart commit SHA")
    source_group.add_argument(
        "--blobheart-dir", help="Path to local blobheart checkout"
    )
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
    args = parser.parse_args()

    ref = args.blobheart_ref
    if ref and not re.fullmatch(r"[0-9a-f]{40}", ref):
        parser.error("--blobheart-ref must be a 40-character lowercase SHA")
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
