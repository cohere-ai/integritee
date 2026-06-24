"""Extract UKI and disk from a podvm OCI image."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


def fetch_uki(podvm_ref: str, dest_dir: Path) -> None:
    """Pull podvm image and extract UKI + disk. Skips if already extracted.

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
