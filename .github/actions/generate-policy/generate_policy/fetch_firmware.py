"""Fetch OVMF firmware from GCE TCB storage by firmware_sha384."""

from __future__ import annotations

import subprocess
from pathlib import Path


def fetch_firmware(sha384: str, dest: Path) -> None:
    """Download a single firmware blob. Skips if dest already exists."""
    if dest.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/{sha384}.fd"
    subprocess.run(["curl", "-fSL", url, "-o", str(dest)], check=True)
    size = dest.stat().st_size / (1024 * 1024)
    print(f"  Fetched firmware: {sha384[:24]}... ({size:.1f}M)")
