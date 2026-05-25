#!/usr/bin/env python3
"""Generate Kata genpolicy outputs and CVM measurements for each model.

For each model this script:
  1. Merges base rules/settings with per-model overrides
  2. Runs genpolicy to produce the rego policy and initdata
  3. Creates a podspec with the initdata annotation injected
  4. Computes TDX measurements using cvm-measure

Usage:
    python generate-measurements.py \
        --models model-a,model-b \
        --models-dir models/ \
        --artifacts-dir artifacts/ \
        --cvm-artifacts-dir cvm-artifacts/ \
        --base-rules rules/rules.rego \
        --base-settings cvm-artifacts/genpolicy-settings-base.json
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


def decode_cc_init_data(initdata_b64: str) -> bytes:
    """Decode a `cc_init_data` annotation value into raw TOML bytes.

    The annotation as injected by Kata is base64(gzip(toml)) — the gzip layer
    keeps the annotation under the etcd value-size limit. Older callers here
    only base64-decoded and wrote the still-gzipped bytes to ``initdata.toml``,
    which silently produced a wrong SHA-384 (RTMR3 prediction matched
    ``sha384(gzipped)`` instead of ``sha384(toml)``).
    """
    raw = base64.b64decode(initdata_b64)
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw)
    return raw


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, **kwargs)


def merge_policy_inputs(
    base_rules: Path,
    base_settings: Path,
    model_dir: Path,
    output_dir: Path,
) -> None:
    run([
        "python3", "scripts/merge-policy-inputs.py",
        "--base-rules", str(base_rules),
        "--base-settings", str(base_settings),
        "--model-dir", str(model_dir),
        "--output-dir", str(output_dir),
    ], check=True)


def run_genpolicy(artifacts: Path) -> None:
    podspec = artifacts / "podspec_original.yaml"
    rules = artifacts / "merged-rules.rego"
    settings = artifacts / "merged-settings.json"

    result = run(
        ["genpolicy", "-y", str(podspec), "-p", str(rules), "-j", str(settings), "-r"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  WARNING: genpolicy -r failed: {result.stderr.strip()}")
    else:
        (artifacts / "kata-policy.rego").write_text(result.stdout)

    result = run(
        ["genpolicy", "-y", str(podspec), "-p", str(rules), "-j", str(settings), "-b"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  WARNING: genpolicy -b failed: {result.stderr.strip()}")
    else:
        (artifacts / "initdata_b64.txt").write_text(result.stdout)


def create_podspec_with_initdata(
    model_dir: Path,
    artifacts: Path,
) -> None:
    initdata_file = artifacts / "initdata_b64.txt"
    podspec_src = model_dir / "podspec.yaml"
    podspec_dest = artifacts / "podspec_with_initdata.yaml"

    if not initdata_file.exists() or not initdata_file.read_text().strip():
        shutil.copy2(podspec_src, podspec_dest)
        return

    initdata_b64 = initdata_file.read_text().strip()

    with open(podspec_src) as f:
        doc = yaml.safe_load(f)

    annotations = doc["spec"]["template"]["metadata"].setdefault("annotations", {})
    annotations["io.katacontainers.config.hypervisor.cc_init_data"] = initdata_b64

    with open(podspec_dest, "w") as f:
        yaml.dump(doc, f, default_flow_style=False)


def compute_measurements(
    artifacts: Path,
    meta: dict,
) -> None:
    initdata_file = artifacts / "initdata_b64.txt"
    measurements_file = artifacts / "measurements.json"

    cmd = [
        "cvm-measure", "tdx",
        "--firmware", meta["firmware_path"],
        "--uki", meta["uki_path"],
        "--baseline", meta["baseline_path"],
        "--ram", str(meta["ram_gib"]),
        "--output-format", "json",
    ]

    if initdata_file.exists() and initdata_file.read_text().strip():
        initdata_b64 = initdata_file.read_text().strip()
        initdata_toml = artifacts / "initdata.toml"
        initdata_toml.write_bytes(decode_cc_init_data(initdata_b64))
        cmd.extend(["--initdata", str(initdata_toml)])
    else:
        print("  WARNING: No initdata, computing without RTMR3")

    result = run(cmd, capture_output=True, text=True, check=True)
    measurements_file.write_text(result.stdout)

    measurements = json.loads(result.stdout)
    print(f"  Measurements: {json.dumps(measurements, indent=2)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate policies and measurements per model",
    )
    parser.add_argument("--models", required=True, help="Comma-separated model names")
    parser.add_argument("--models-dir", required=True)
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--cvm-artifacts-dir", required=True)
    parser.add_argument("--base-rules", required=True)
    parser.add_argument("--base-settings", required=True)
    args = parser.parse_args()

    models_dir = Path(args.models_dir)
    artifacts_dir = Path(args.artifacts_dir)
    cvm_artifacts_dir = Path(args.cvm_artifacts_dir)
    base_rules = Path(args.base_rules)
    base_settings = Path(args.base_settings)

    for model in args.models.split(","):
        model = model.strip()
        if not model:
            continue

        print("=" * 50)
        print(f"Processing model: {model}")
        print("=" * 50)

        model_dir = models_dir / model
        model_artifacts = artifacts_dir / model
        model_artifacts.mkdir(parents=True, exist_ok=True)

        meta_path = cvm_artifacts_dir / model / "meta.json"
        meta = json.loads(meta_path.read_text())

        initdata_file = model_artifacts / "initdata_b64.txt"
        if initdata_file.exists() and initdata_file.read_text().strip():
            print("  Using pre-fetched initdata (genpolicy skipped)")
        else:
            # TODO: re-enable once the full podspec can be encoded in this repo.
            # merge_policy_inputs(base_rules, base_settings, model_dir, model_artifacts)
            # shutil.copy2(model_dir / "podspec.yaml", model_artifacts / "podspec_original.yaml")
            # run_genpolicy(model_artifacts)
            # create_podspec_with_initdata(model_dir, model_artifacts)
            print("  WARNING: No pre-fetched initdata and genpolicy is disabled")

        compute_measurements(model_artifacts, meta)

        print(f"Completed: {model}\n")


if __name__ == "__main__":
    main()
