"""Fetch CVM artifacts: TDX baselines, OVMF firmware, and PodVM UKI/disk."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

BASELINE_ROOT = "baselines/gcp/tdx"
BASELINE_DEFAULTS = f"{BASELINE_ROOT}/defaults.json"
FIRMWARE_RE = re.compile(r"^[0-9a-f]{96}$")
MACHINE_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
VERSION_RE = re.compile(r"^v([1-9][0-9]*)$")


def _gh_api(api_path: str, *, allow_not_found: bool = False) -> object | None:
    result = subprocess.run(
        ["gh", "api", api_path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        if allow_not_found and "HTTP 404" in result.stderr:
            return None
        result.check_returncode()
    return json.loads(result.stdout)


def _fetch_baseline_path(repo: str, path: str) -> dict:
    response = _gh_api(f"/repos/{repo}/contents/{path}")
    if not isinstance(response, dict) or not isinstance(response.get("content"), str):
        raise ValueError(f"invalid GitHub contents response for {path}")
    baseline = _decode_baseline_content(response["content"], path)
    if not isinstance(baseline, dict):
        raise ValueError(f"baseline {path} is not a JSON object")
    print(f"  Baseline: firmware={baseline['firmware_sha384'][:24]}..., events={len(baseline['events'])}")
    return baseline


def _decode_baseline_content(content: str, path: str) -> dict:
    encoded = "".join(content.split())
    try:
        return json.loads(base64.b64decode(encoded, validate=True))
    except (binascii.Error, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid baseline content for {path}") from exc


def _resolve_default_baseline(
    repo: str,
    machine_type: str,
) -> tuple[dict, str, str]:
    """Resolve a machine's default to an immutable baseline version."""
    if not REPO_RE.fullmatch(repo):
        raise ValueError(f"invalid GitHub repository: {repo}")
    if not MACHINE_TYPE_RE.fullmatch(machine_type):
        raise ValueError(f"invalid machine type: {machine_type}")

    response = _gh_api(
        f"/repos/{repo}/contents/{BASELINE_DEFAULTS}",
        allow_not_found=True,
    )
    if response is None:
        legacy_path = f"{BASELINE_ROOT}/{machine_type}.json"
        return _fetch_baseline_path(repo, legacy_path), legacy_path, "current"
    if not isinstance(response, dict) or not isinstance(response.get("content"), str):
        raise ValueError(f"invalid GitHub contents response for {BASELINE_DEFAULTS}")

    defaults = _decode_baseline_content(response["content"], BASELINE_DEFAULTS)
    default = defaults.get(machine_type)
    if not isinstance(default, dict):
        raise ValueError(f"no default baseline for machine type {machine_type}")
    firmware = default.get("firmware_sha384")
    version = default.get("version")
    if not isinstance(firmware, str) or not FIRMWARE_RE.fullmatch(firmware):
        raise ValueError(f"invalid default firmware for machine type {machine_type}")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ValueError(f"invalid default version for machine type {machine_type}")

    path = f"{BASELINE_ROOT}/versions/{firmware}/{version}/{machine_type}.json"
    baseline = _fetch_baseline_path(repo, path)
    if baseline.get("machine_type") != machine_type:
        raise ValueError(f"baseline machine type does not match default for {path}")
    if baseline.get("firmware_sha384") != firmware:
        raise ValueError(f"baseline firmware does not match default for {path}")
    return baseline, path, version


def fetch_baseline(repo: str, machine_type: str) -> dict:
    """Fetch the resolved default TDX baseline JSON."""
    baseline, _, _ = _resolve_default_baseline(repo, machine_type)
    return baseline


def fetch_baseline_variants(repo: str, machine_type: str) -> list[dict]:
    """Fetch every versioned baseline with the configured default first."""
    default, default_path, default_version = _resolve_default_baseline(
        repo,
        machine_type,
    )
    versions_path = f"{BASELINE_ROOT}/versions"
    firmware_entries = _gh_api(
        f"/repos/{repo}/contents/{versions_path}",
        allow_not_found=True,
    )
    if firmware_entries is None:
        return [{
            "version": default_version,
            "firmware_sha384": default["firmware_sha384"],
            "baseline": default,
            "baseline_ref": f"{repo}/{default_path}",
        }]
    if not isinstance(firmware_entries, list):
        raise ValueError(f"{versions_path} is not a directory")

    variants: list[dict] = []
    firmware_names = sorted(
        entry["name"]
        for entry in firmware_entries
        if (
            isinstance(entry, dict)
            and entry.get("type") == "dir"
            and isinstance(entry.get("name"), str)
            and FIRMWARE_RE.fullmatch(entry["name"])
        )
    )
    for firmware in firmware_names:
        firmware_path = f"{versions_path}/{firmware}"
        version_entries = _gh_api(f"/repos/{repo}/contents/{firmware_path}")
        if not isinstance(version_entries, list):
            raise ValueError(f"{firmware_path} is not a directory")

        version_names = sorted(
            (
                entry["name"]
                for entry in version_entries
                if (
                    isinstance(entry, dict)
                    and entry.get("type") == "dir"
                    and isinstance(entry.get("name"), str)
                    and VERSION_RE.fullmatch(entry["name"])
                )
            ),
            key=lambda version: int(VERSION_RE.fullmatch(version).group(1)),
        )
        for version in version_names:
            path = f"{firmware_path}/{version}/{machine_type}.json"
            response = _gh_api(
                f"/repos/{repo}/contents/{path}",
                allow_not_found=True,
            )
            if response is None:
                continue
            if not isinstance(response, dict) or not isinstance(response.get("content"), str):
                raise ValueError(f"invalid GitHub contents response for {path}")
            baseline = _decode_baseline_content(response["content"], path)
            if baseline.get("firmware_sha384") != firmware:
                raise ValueError(
                    f"baseline firmware does not match directory for {path}"
                )
            variants.append({
                "version": version,
                "firmware_sha384": firmware,
                "baseline": baseline,
                "baseline_ref": f"{repo}/{path}",
            })

    if variants:
        default_ref = f"{repo}/{default_path}"
        if not any(variant["baseline_ref"] == default_ref for variant in variants):
            matching_defaults = [
                variant
                for variant in variants
                if variant["baseline"] == default
            ]
            if not matching_defaults:
                raise ValueError(
                    f"default baseline was not discovered under {versions_path}: "
                    f"{default_path}"
                )
            default_ref = matching_defaults[0]["baseline_ref"]
        variants.sort(key=lambda variant: variant["baseline_ref"] != default_ref)
        print(f"  Found {len(variants)} versioned baseline(s)")
        return variants

    return [{
        "version": default_version,
        "firmware_sha384": default["firmware_sha384"],
        "baseline": default,
        "baseline_ref": f"{repo}/{default_path}",
    }]


def fetch_firmware(fw_sha384: str, dest: Path) -> None:
    """Download and verify an OVMF firmware blob by its SHA-384."""
    if not FIRMWARE_RE.fullmatch(fw_sha384):
        raise ValueError(f"invalid firmware SHA-384: {fw_sha384}")

    def verify(path: Path) -> None:
        actual = hashlib.sha384(path.read_bytes()).hexdigest()
        if actual != fw_sha384:
            path.unlink(missing_ok=True)
            raise ValueError(
                f"firmware hash mismatch: expected {fw_sha384}, got {actual}"
            )

    if dest.exists():
        verify(dest)
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/{fw_sha384}.fd"
    with tempfile.NamedTemporaryFile(
        dir=dest.parent,
        prefix=f".{dest.name}.",
        delete=False,
    ) as output:
        temp_path = Path(output.name)
    try:
        subprocess.run(
            [
                "curl", "-fSL",
                "--connect-timeout", "10",
                "--max-time", "120",
                url,
                "-o", str(temp_path),
            ],
            check=True,
        )
        verify(temp_path)
        temp_path.replace(dest)
    finally:
        temp_path.unlink(missing_ok=True)
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
