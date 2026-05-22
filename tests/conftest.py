"""Shared fixtures for model-integrity tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent

REAL_MEASUREMENTS = {
    "mrtd": "8370d8f6d02f2d13e211e91c93fde923049522b241425a29a7bf0071ef49b250af4ef49d852fa3e10065d1b51dfce8fb",
    "rtmr0": "65f60f9929a36b146f69063f6b2d67dff42ea3cda500cb637cf655c29427c4710cca4e8abd7f32a7f1c2622f27cbb4d2",
    "rtmr1": "c35bbfad7ba5d703b2f78e0741e69a18a6f6093319af8440c8e3384b684e39947769dff3ba268c25d632f7459452e239",
    "rtmr2": "e03c2e6378a0d0b66ced6612e58dbc5bea8b8a7183055e5674602bd7b2da79a69dc1148fd9646ba03b71672473670d90",
    "rtmr3": "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f0718293a4b5c6d7e8f901a2b3c4d5e6f0718293a4b5c6d7e8f90",
}

STATIC_REF_VALS = {
    "tdx_mrseam": "a" * 96,
    "tdx_mrsignerseam": "0" * 96,
    "tdx_mrconfigid": "0" * 96,
    "tdx_mrowner": "0" * 96,
    "tdx_mrownerconfig": "0" * 96,
    "tdx_seam_attributes": "0000000000000000",
    "tdx_td_attributes": "0000001000000000",
    "tdx_tee_tcb_svn": "0d010800000000000000000000000000",
    "tdx_seamsvn": 269,
}


@pytest.fixture
def real_measurements() -> dict:
    return REAL_MEASUREMENTS.copy()


@pytest.fixture
def static_ref_vals() -> dict:
    return STATIC_REF_VALS.copy()


@pytest.fixture
def static_ref_vals_path(tmp_path: Path, static_ref_vals: dict) -> Path:
    p = tmp_path / "tdx-static-ref-vals.yaml"
    p.write_text(yaml.dump(static_ref_vals, default_flow_style=False))
    return p


@pytest.fixture
def artifacts_dir(tmp_path: Path, real_measurements: dict) -> Path:
    """Create a realistic artifacts directory with two models."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()

    for model, meas_override in [
        ("command-r-plus", {}),
        ("aya-expanse", {"mrtd": "1" * 96, "rtmr0": "2" * 96, "rtmr1": "3" * 96, "rtmr2": "4" * 96, "rtmr3": "5" * 96}),
    ]:
        model_dir = artifacts / model
        model_dir.mkdir()

        m = {**real_measurements, **meas_override}
        (model_dir / "measurements.json").write_text(json.dumps(m))
        (model_dir / "policy.rego").write_text(
            "package agent_policy\nimport rego.v1\ndefault match := false\n"
        )
        (model_dir / "initdata_b64.txt").write_text("dGVzdGluaXRkYXRh")

    return artifacts


DEFAULT_CVM_META = {
    "machine_type": "a3-highgpu-1g",
    "podvm_image_tag": "cohere-latest-ubuntu-debug",
    "ram_gib": 234,
    "baseline_path": "cvm-artifacts/baselines/a3-highgpu-1g.json",
    "baseline_ref": "cohere-ai/cohere-cc-baselines/baselines/gcp/tdx/a3-highgpu-1g.json",
    "firmware_path": "cvm-artifacts/firmware/abc.fd",
    "firmware_ref": "ovmf-2024-08",
    "uki_path": "cvm-artifacts/uki/cohere-latest-ubuntu-debug/BOOTX64.EFI",
    "uki_ref": "sha384:abc",
}


def make_cvm_artifacts_dir(
    base_path: Path,
    models: list[str] | None = None,
    overrides: dict[str, dict] | None = None,
) -> Path:
    """Create a cvm-artifacts directory with per-model meta.json files."""
    cvm_dir = base_path / "cvm-artifacts"
    cvm_dir.mkdir(exist_ok=True)

    if models is None:
        models = ["command-r-plus", "aya-expanse"]
    if overrides is None:
        overrides = {}

    for model in models:
        model_dir = cvm_dir / model
        model_dir.mkdir(exist_ok=True)
        meta = {**DEFAULT_CVM_META, **overrides.get(model, {})}
        (model_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    return cvm_dir


@pytest.fixture
def cvm_artifacts_dir(tmp_path: Path) -> Path:
    """Create a cvm-artifacts directory with default meta.json files."""
    return make_cvm_artifacts_dir(tmp_path)


@pytest.fixture
def schema_path() -> Path:
    return REPO_ROOT / "schemas" / "predicate-v1.schema.json"


@pytest.fixture
def template_path() -> Path:
    return REPO_ROOT / "attestation-policy" / "template.rego"
