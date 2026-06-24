"""Fetch CVM artifacts: TDX baselines, OVMF firmware, and PodVM UKI/disk."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def fetch_baseline(repo: str, machine_type: str) -> dict:
    """Fetch a TDX baseline JSON from cohere-cc-baselines and return it."""
    api_path = f"/repos/{repo}/contents/baselines/gcp/tdx/{machine_type}.json"
    result = subprocess.run(
        ["gh", "api", api_path, "--jq", ".content"],
        capture_output=True, text=True, check=True,
    )
    baseline = json.loads(base64.b64decode(result.stdout.strip()))
    print(f"  Baseline: firmware={baseline['firmware_sha384'][:24]}..., events={len(baseline['events'])}")
    return baseline


def fetch_firmware(fw_sha384: str, dest: Path) -> None:
    """Download an OVMF firmware blob by its SHA-384. Skips if dest exists."""
    if dest.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/{fw_sha384}.fd"
    subprocess.run(["curl", "-fSL", url, "-o", str(dest)], check=True)
    size = dest.stat().st_size / (1024 * 1024)
    print(f"  Firmware: {fw_sha384[:24]}... ({size:.1f}M)")


def fetch_oci_digest(ref: str) -> str:
    """Fetch the content digest of an OCI reference (e.g. sha256:abc...)."""
    result = subprocess.run(
        ["oras", "resolve", ref],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def fetch_uki(podvm_ref: str, dest_dir: Path) -> None:
    """Pull podvm OCI image and extract UKI + disk. Skips if already extracted.

    Produces:
      dest_dir/BOOTX64.EFI
      dest_dir/disk.tar.gz
      dest_dir/measurements.json  (if present in the image)
    """
    uki_path = dest_dir / "BOOTX64.EFI"
    if uki_path.exists() and (dest_dir / "disk.tar.gz").exists():
        return
    dest_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="podvm-") as work_dir:
        subprocess.run(["oras", "pull", podvm_ref], cwd=work_dir, check=True)

        subprocess.run(
            ["cvm-measure", "extract-uki",
             "--disk", str(Path(work_dir) / "disk.tar.gz"),
             "--output", str(uki_path)],
            check=True,
        )

        shutil.copy2(Path(work_dir) / "disk.tar.gz", dest_dir / "disk.tar.gz")

        meas_src = Path(work_dir) / "measurements.json"
        if meas_src.exists():
            shutil.copy2(meas_src, dest_dir / "measurements.json")

    size = uki_path.stat().st_size / (1024 * 1024)
    print(f"  Extracted UKI ({size:.1f}M)")
