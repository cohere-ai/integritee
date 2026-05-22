#!/usr/bin/env python3
"""Extract UKI from podvm images for each model.

Reads podvm_image_tag from each model's meta.json, pulls the OCI artifact
via oras, and extracts the UKI using cvm-measure. Deduplicates by
podvm_image_tag so identical images are processed only once.

Requires PODVM_IMAGE environment variable.

Usage:
    python fetch-uki.py \
        --models model-a,model-b \
        --cvm-artifacts-dir cvm-artifacts/
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def extract_uki(podvm_ref: str, dest: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="podvm-") as work_dir:
        subprocess.run(
            ["oras", "pull", podvm_ref],
            cwd=work_dir, check=True,
        )

        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["cvm-measure", "extract-uki",
             "--disk", str(Path(work_dir) / "disk.tar.gz"),
             "--output", str(dest)],
            check=True,
        )

    size = dest.stat().st_size / (1024 * 1024)
    print(f"  UKI extracted ({size:.1f}M)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract UKI per model")
    parser.add_argument("--models", required=True, help="Comma-separated model names")
    parser.add_argument("--cvm-artifacts-dir", required=True)
    args = parser.parse_args()

    podvm_image = os.environ["PODVM_IMAGE"]
    cvm_dir = Path(args.cvm_artifacts_dir)
    uki_dir = cvm_dir / "uki"
    uki_dir.mkdir(parents=True, exist_ok=True)

    for model in args.models.split(","):
        model = model.strip()
        if not model:
            continue

        meta_path = cvm_dir / model / "meta.json"
        meta = json.loads(meta_path.read_text())

        podvm_tag = meta["podvm_image_tag"]
        podvm_ref = f"{podvm_image}:{podvm_tag}"
        uki_dest = uki_dir / podvm_tag / "BOOTX64.EFI"

        if uki_dest.exists():
            print(f"{model}: reusing cached UKI for {podvm_tag}")
        else:
            print(f"{model}: extracting UKI from {podvm_ref}")
            extract_uki(podvm_ref, uki_dest)

        meta["uki_path"] = str(uki_dest)
        meta["uki_ref"] = podvm_ref
        meta_path.write_text(json.dumps(meta, indent=2) + "\n")

    print("UKI extraction complete")


if __name__ == "__main__":
    main()
