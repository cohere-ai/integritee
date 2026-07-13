"""Compute TDX measurements for a single target using cvm-measure."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def resolve_initdata(target: dict, manifest_file: Path) -> bytes:
    """Load and verify file-backed target initdata."""
    if "initdata_b64" in target:
        raise ValueError("initdata_b64 is not supported")

    digest = target.get("initdata_sha384")
    relative = target.get("initdata_file")
    expected_relative = f"initdata/{digest}.toml"
    if (
        not isinstance(digest, str)
        or len(digest) != 96
        or any(character not in "0123456789abcdef" for character in digest)
        or relative != expected_relative
    ):
        raise ValueError("target has invalid file-backed initdata")

    initdata_path = manifest_file.parent / expected_relative
    if not initdata_path.is_file():
        raise ValueError(f"initdata file does not exist: {relative}")
    initdata = initdata_path.read_bytes()
    actual_digest = hashlib.sha384(initdata).hexdigest()
    if actual_digest != digest:
        raise ValueError(
            f"initdata digest mismatch: expected {digest}, got {actual_digest}"
        )
    return initdata


def compute_measurements(
    ram_gib: int,
    initdata: bytes,
    firmware_path: Path,
    baseline_path: Path,
    uki_path: Path,
    disk_path: Path,
    output_dir: Path,
) -> dict:
    """Compute TDX measurements and write measurements.json."""
    output_dir.mkdir(parents=True, exist_ok=True)

    initdata_toml = output_dir / "initdata.toml"
    initdata_toml.write_bytes(initdata)

    cmd = [
        "cvm-measure", "tdx",
        "--firmware", str(firmware_path),
        "--uki", str(uki_path),
        "--disk", str(disk_path),
        "--baseline", str(baseline_path),
        "--ram", str(ram_gib),
        "--initdata", str(initdata_toml),
        "--output-format", "json",
    ]

    print(f"  $ {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        if exc.stdout:
            print(exc.stdout, file=sys.stdout)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        raise

    measurements_file = output_dir / "measurements.json"
    measurements_file.write_text(result.stdout)

    measurements = json.loads(result.stdout)
    print(f"  Measurements: {json.dumps(measurements, indent=2)}")
    return measurements
