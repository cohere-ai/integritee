"""Entrypoint for the generate-policy Docker action.

Reads a policy manifest YAML, fetches CVM artifacts, computes measurements,
and renders an ITA attestation policy.

Invoked via: python -m generate_policy
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

from .fetch_baselines import fetch_baseline
from .fetch_firmware import fetch_firmware
from .fetch_uki import fetch_uki
from .measurements import compute_measurements
from .ita_policy import generate_policy


def main() -> None:
    manifest_file = os.environ.get("INPUT_MANIFEST_FILE", "")
    if not manifest_file:
        print("ERROR: manifest-file input is required", file=sys.stderr)
        sys.exit(1)

    manifest_path = Path(manifest_file)
    if not manifest_path.exists():
        print(f"ERROR: manifest file not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    doc = yaml.safe_load(manifest_path.read_text()) or {}
    targets = doc.get("targets", [])
    if not targets:
        print("ERROR: no targets in manifest", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(targets)} targets from {manifest_path}")
    for t in targets:
        print(f"  - {t.get('model')}: {t.get('machine_type')} / {t.get('podvm_image_tag')}")

    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "/github/workspace"))
    baselines_repo = os.environ["BASELINES_REPO"]
    podvm_image = os.environ["PODVM_IMAGE"]

    artifacts_dir = workspace / "artifacts"
    cvm_dir = workspace / "cvm-artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    cvm_dir.mkdir(parents=True, exist_ok=True)

    baselines_dir = cvm_dir / "baselines"
    firmware_dir = cvm_dir / "firmware"
    uki_dir = cvm_dir / "uki"

    for target in targets:
        model = target["model"]
        machine_type = target["machine_type"]
        podvm_tag = target["podvm_image_tag"]

        print(f"\n{'=' * 60}")
        print(f"Processing: {model}")
        print(f"{'=' * 60}")

        # 1. Baseline (deduped by machine_type via file existence)
        baseline_path = baselines_dir / f"{machine_type}.json"
        print(f"  Baseline: {machine_type}")
        fetch_baseline(baselines_repo, machine_type, baseline_path)

        # 2. Firmware (deduped by sha384 via file existence)
        baseline_data = json.loads(baseline_path.read_text())
        fw_sha384 = baseline_data["firmware_sha384"]
        firmware_path = firmware_dir / f"{fw_sha384}.fd"
        print(f"  Firmware: {fw_sha384[:24]}...")
        fetch_firmware(fw_sha384, firmware_path)

        # 3. UKI (deduped by podvm_tag via file existence)
        podvm_ref = f"{podvm_image}:{podvm_tag}"
        uki_dest = uki_dir / podvm_tag
        print(f"  UKI: {podvm_tag}")
        fetch_uki(podvm_ref, uki_dest)

        # 4. Measurements (per target, always computed)
        model_artifacts = artifacts_dir / model
        print(f"  Computing measurements...")
        compute_measurements(
            model=model,
            ram_gib=target["ram_gib"],
            initdata_b64=target.get("initdata_b64", ""),
            firmware_path=firmware_path,
            baseline_path=baseline_path,
            uki_path=uki_dest / "BOOTX64.EFI",
            disk_path=uki_dest / "disk.tar.gz",
            output_dir=model_artifacts,
        )

        # Write meta.json for build-predicate.py
        meta = {
            "machine_type": machine_type,
            "podvm_image_tag": podvm_tag,
            "ram_gib": target["ram_gib"],
            "firmware_ref": fw_sha384,
            "baseline_ref": f"{baselines_repo}/baselines/gcp/tdx/{machine_type}.json",
            "uki_ref": podvm_ref,
        }
        meta_dir = cvm_dir / model
        meta_dir.mkdir(parents=True, exist_ok=True)
        (meta_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    # 5. Render ITA policy from all measurements
    print(f"\n{'=' * 60}")
    print("Generating ITA policy")
    print(f"{'=' * 60}")
    template_path = Path(__file__).parent / "attestation-policy" / "template.rego"
    policy_output = artifacts_dir / "ita-attestation-policy.rego"
    generate_policy(artifacts_dir, cvm_dir, template_path, policy_output)

    # Collect outputs
    try:
        cvm_ver = subprocess.run(
            ["pip", "show", "cvm-measure"],
            capture_output=True, text=True,
        ).stdout
        cvm_measure_version = next(
            (l.split(":")[1].strip() for l in cvm_ver.splitlines()
             if l.startswith("Version:")), "unknown"
        )
    except Exception:
        cvm_measure_version = "unknown"

    model_list = ",".join(t["model"] for t in targets)

    github_output = os.environ.get("GITHUB_OUTPUT", "")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"policy-file={policy_output}\n")
            f.write(f"measurements-dir={artifacts_dir}\n")
            f.write(f"cvm-artifacts-dir={cvm_dir}\n")
            f.write(f"cvm-measure-version={cvm_measure_version}\n")
            f.write(f"models={model_list}\n")

    print(f"\nDone. Policy: {policy_output}")


main()
