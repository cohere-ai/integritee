#!/usr/bin/env python3
"""Derive a policy manifest from a blobheart ref or local checkout.

Discovers CC models, extracts initdata, derives machine_type/podvm_image_tag
from kustomization.yaml, and looks up ram_gib from a static machine-types.yaml.

Hardcoded blobheart paths:
  - CC models: k8s/geofence/components/models_v2/generated/<model>-cc/
  - Kustomization: k8s/geofence/components/models_v2/base/kustomization.yaml
  - Initdata: <model>-cc/kata-policy-patch.yaml (cc_init_data annotation)

Usage (remote):
    GH_TOKEN=... python derive.py \
        --blobheart-ref <commit-sha> \
        --output /tmp/derived-manifest.yaml

Usage (local):
    python derive.py \
        --blobheart-dir /path/to/blobheart \
        --output /tmp/derived-manifest.yaml
"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

BLOBHEART_REPO = "cohere-ai/blobheart"
GENERATED_DIR = "k8s/geofence/components/models_v2/generated"
KUSTOMIZATION_PATH = "k8s/geofence/components/models_v2/base/kustomization.yaml"
CC_SUFFIX = "-cc"

GPU_LABEL_KEY = "cohere.com/gpu"
CC_LABEL = "cohere.com/confidential-compute=true"

KATA_IMAGE_ANNOTATION = "io.katacontainers.config.hypervisor.image"
KATA_MACHINE_ANNOTATION = "io.katacontainers.config.hypervisor.machine_type"


def read_file(root: Path | None, ref: str | None, path: str) -> str:
    """Read a file from a local dir or the GitHub API."""
    if root:
        return (root / path).read_text()
    api_path = f"/repos/{BLOBHEART_REPO}/contents/{path}?ref={ref}"
    result = subprocess.run(
        ["gh", "api", api_path, "--jq", ".content"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"ERROR: gh api {api_path}: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return base64.b64decode(result.stdout.strip()).decode()


def list_dir(root: Path | None, ref: str | None, path: str) -> list[str]:
    """List subdirectory names from a local dir or the GitHub API."""
    if root:
        return sorted(e.name for e in (root / path).iterdir() if e.is_dir())
    api_path = f"/repos/{BLOBHEART_REPO}/contents/{path}?ref={ref}"
    result = subprocess.run(
        ["gh", "api", api_path, "--jq", ".[].name"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"ERROR: gh api {api_path}: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return [name.strip() for name in result.stdout.strip().split("\n") if name.strip()]


def build_cc_label_map(kustomization_yaml: str) -> dict[str, dict]:
    """Build GPU label -> {machine_type, podvm_image_tag} from CC patches.

    CC patches are identified by their target labelSelector containing both
    cohere.com/gpu=<label> and cohere.com/confidential-compute=true. The
    patch body's kata annotations provide machine_type and podvm image.
    """
    doc = yaml.safe_load(kustomization_yaml)
    label_map: dict[str, dict] = {}

    for patch in doc.get("patches", []):
        selector = patch.get("target", {}).get("labelSelector", "")
        if CC_LABEL not in selector:
            continue

        gpu_match = re.search(rf"{re.escape(GPU_LABEL_KEY)}=([^,]+)", selector)
        if not gpu_match:
            continue
        gpu_label = gpu_match.group(1)

        patch_content = patch.get("patch", "")
        if not patch_content:
            continue
        try:
            patch_doc = yaml.safe_load(patch_content)
        except yaml.YAMLError:
            continue
        if not isinstance(patch_doc, dict):
            continue

        annotations = (
            patch_doc.get("spec", {})
            .get("template", {})
            .get("metadata", {})
            .get("annotations", {})
        )

        machine_type = annotations.get(KATA_MACHINE_ANNOTATION)
        image_ref = annotations.get(KATA_IMAGE_ANNOTATION, "")
        podvm_image_tag = image_ref.rsplit("/", 1)[-1] if image_ref else ""

        if machine_type:
            label_map[gpu_label] = {
                "machine_type": machine_type,
                "podvm_image_tag": podvm_image_tag,
            }

    return label_map


def extract_initdata(kata_policy_yaml: str) -> str | None:
    """Extract cc_init_data annotation from kata-policy-patch.yaml."""
    doc = yaml.safe_load(kata_policy_yaml)
    if not doc:
        return None
    annotations = (
        doc.get("spec", {})
        .get("template", {})
        .get("metadata", {})
        .get("annotations", {})
    )
    return annotations.get("io.katacontainers.config.hypervisor.cc_init_data")


def extract_gpu_label(model_yaml: str) -> str | None:
    """Extract cohere.com/gpu label from a model's model.yaml.

    model.yaml is a multi-document YAML file containing all K8s resources.
    The GPU label is on the StatefulSet's metadata labels.
    """
    for doc in yaml.safe_load_all(model_yaml):
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") != "StatefulSet":
            continue
        labels = doc.get("metadata", {}).get("labels", {})
        gpu = labels.get(GPU_LABEL_KEY)
        if gpu:
            return gpu
    return None


def load_machine_types() -> dict[str, dict]:
    """Load static machine type -> ram_gib mapping."""
    mt_path = Path(__file__).parent / "machine-types.yaml"
    return yaml.safe_load(mt_path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser(description="Derive manifest from blobheart ref or local checkout")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--blobheart-ref", help="Blobheart commit SHA")
    source_group.add_argument("--blobheart-dir", help="Path to local blobheart checkout")
    parser.add_argument("--output", required=True, help="Output manifest YAML path")
    args = parser.parse_args()

    root = Path(args.blobheart_dir) if args.blobheart_dir else None
    ref = args.blobheart_ref
    source_label = f"local://{root}" if root else f"blobheart://{ref}"

    machine_types = load_machine_types()
    print(f"Deriving manifest from {source_label}")

    entries = list_dir(root, ref, GENERATED_DIR)
    cc_models = [e for e in entries if e.endswith(CC_SUFFIX)]
    print(f"Found {len(cc_models)} CC models: {', '.join(cc_models)}")

    if not cc_models:
        print("No CC models found, writing empty manifest")
        Path(args.output).write_text(yaml.dump({"targets": []}, sort_keys=False))
        return

    kustomization = read_file(root, ref, KUSTOMIZATION_PATH)
    label_map = build_cc_label_map(kustomization)
    print(f"CC label map: {json.dumps({k: v.get('machine_type', '?') for k, v in label_map.items()})}")

    if not label_map:
        print("WARNING: no CC patches found in kustomization.yaml")

    targets: list[dict] = []

    for cc_name in cc_models:
        model = cc_name.removesuffix(CC_SUFFIX)
        print(f"\n--- {model} ({cc_name}) ---")

        model_path = f"{GENERATED_DIR}/{cc_name}/model.yaml"
        try:
            model_raw = read_file(root, ref, model_path)
            gpu_label = extract_gpu_label(model_raw)
        except SystemExit:
            print(f"  WARNING: could not read model.yaml, skipping")
            continue

        if not gpu_label:
            print(f"  WARNING: no {GPU_LABEL_KEY} label on StatefulSet, skipping")
            continue
        print(f"  GPU label: {gpu_label}")

        label_info = label_map.get(gpu_label)
        if not label_info:
            print(f"  WARNING: no CC patch for {gpu_label}, skipping")
            continue

        machine_type = label_info["machine_type"]
        podvm_image_tag = label_info["podvm_image_tag"]

        mt_info = machine_types.get(machine_type)
        if not mt_info:
            print(f"  ERROR: unknown machine type '{machine_type}' -- "
                  "update machine-types.yaml", file=sys.stderr)
            sys.exit(1)
        ram_gib = mt_info["ram_gib"]

        kata_path = f"{GENERATED_DIR}/{cc_name}/kata-policy-patch.yaml"
        try:
            kata_raw = read_file(root, ref, kata_path)
            initdata = extract_initdata(kata_raw)
        except SystemExit:
            print(f"  WARNING: could not read kata-policy-patch.yaml, skipping")
            continue

        if not initdata:
            print(f"  WARNING: no cc_init_data annotation, skipping")
            continue

        today = datetime.date.today().isoformat()
        target = {
            "model": model,
            "machine_type": machine_type,
            "podvm_image_tag": podvm_image_tag,
            "ram_gib": ram_gib,
            "initdata_b64": initdata,
            "added": today,
            "sources": [ref] if ref else ["local"],
        }
        targets.append(target)
        print(f"  Derived: {machine_type}, {podvm_image_tag}, "
              f"ram_gib={ram_gib}, initdata={len(initdata)} chars")

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(
        yaml.dump({"targets": targets}, default_flow_style=False, sort_keys=False)
    )
    print(f"\nDerived {len(targets)} targets -> {args.output}")


if __name__ == "__main__":
    main()
