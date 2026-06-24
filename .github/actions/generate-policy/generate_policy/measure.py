"""Compute TDX measurements for a single target using cvm-measure."""

from __future__ import annotations

import base64
import gzip
import json
import subprocess
from pathlib import Path


def decode_cc_init_data(initdata_b64: str) -> bytes:
    """Decode a cc_init_data annotation value into raw TOML bytes.

    The annotation is base64(gzip(toml)) -- the gzip layer keeps the
    annotation under the etcd value-size limit.
    """
    raw = base64.b64decode(initdata_b64)
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw)
    return raw


def compute_measurements(
    ram_gib: int,
    initdata_b64: str,
    firmware_path: Path,
    baseline_path: Path,
    uki_path: Path,
    disk_path: Path,
    output_dir: Path,
) -> dict:
    """Compute TDX measurements and write measurements.json."""
    output_dir.mkdir(parents=True, exist_ok=True)

    initdata_toml = output_dir / "initdata.toml"
    initdata_toml.write_bytes(decode_cc_init_data(initdata_b64))

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
