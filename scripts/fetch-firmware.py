#!/usr/bin/env python3
"""Fetch OVMF firmware for each model based on its resolved baseline.

Reads baseline_path from each model's meta.json, extracts firmware_sha384
from the baseline, and downloads the OVMF firmware from GCE TCB storage.
Deduplicates by firmware_sha384 so identical firmware is fetched only once.

Usage:
    python fetch-firmware.py \
        --models model-a,model-b \
        --cvm-artifacts-dir cvm-artifacts/
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def download_firmware(sha384: str, dest: Path) -> None:
    url = f"https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/{sha384}.fd"
    subprocess.run(
        ["curl", "-fSL", url, "-o", str(dest)],
        check=True,
    )
    size = dest.stat().st_size / (1024 * 1024)
    print(f"  Downloaded {size:.1f}M")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch OVMF firmware per model")
    parser.add_argument("--models", required=True, help="Comma-separated model names")
    parser.add_argument("--cvm-artifacts-dir", required=True)
    args = parser.parse_args()

    cvm_dir = Path(args.cvm_artifacts_dir)
    firmware_dir = cvm_dir / "firmware"
    firmware_dir.mkdir(parents=True, exist_ok=True)

    for model in args.models.split(","):
        model = model.strip()
        if not model:
            continue

        meta_path = cvm_dir / model / "meta.json"
        meta = json.loads(meta_path.read_text())

        baseline = json.loads(Path(meta["baseline_path"]).read_text())
        fw_sha384 = baseline["firmware_sha384"]

        firmware_dest = firmware_dir / f"{fw_sha384}.fd"

        if firmware_dest.exists():
            print(f"{model}: reusing cached firmware {fw_sha384[:24]}...")
        else:
            print(f"{model}: fetching firmware {fw_sha384[:24]}...")
            download_firmware(fw_sha384, firmware_dest)

        meta["firmware_path"] = str(firmware_dest)
        meta["firmware_ref"] = fw_sha384
        meta_path.write_text(json.dumps(meta, indent=2) + "\n")

    print("Firmware complete")


if __name__ == "__main__":
    main()
