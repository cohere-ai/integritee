"""Tests for the ITA attestation policy generator.

These tests exercise the actual script (scripts/generate-ita-policy.py)
with real measurement data and verify the generated Rego policy structure
matches the tdx_h100_pp_image shape expected by ITA.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT


def run_generate_script(
    measurements_dir: Path,
    template_path: Path,
    output_path: Path,
    nonce: str = "test-nonce-001",
    cvm_artifacts_dir: Path | None = None,
    temporary_gcp_tdx_firmware_allowlist: Path | None = None,
) -> subprocess.CompletedProcess:
    if cvm_artifacts_dir is None:
        cvm_artifacts_dir = measurements_dir.parent / "cvm-artifacts"
        (cvm_artifacts_dir / "uki" / "test-podvm").mkdir(parents=True, exist_ok=True)
        (
            cvm_artifacts_dir
            / "uki"
            / "test-podvm"
            / "measurements.json"
        ).write_text(json.dumps({"nvidia_driver_version": "580.159.04-1ubuntu1"}))

        for model_dir in measurements_dir.iterdir():
            if not model_dir.is_dir():
                continue
            meta_dir = cvm_artifacts_dir / model_dir.name
            meta_dir.mkdir(parents=True, exist_ok=True)
            (meta_dir / "meta.json").write_text(
                json.dumps({"podvm_image_tag": "test-podvm"})
            )

    if temporary_gcp_tdx_firmware_allowlist is None:
        temporary_gcp_tdx_firmware_allowlist = (
            measurements_dir.parent / "empty-temporary-firmware-allowlist.json"
        )
        temporary_gcp_tdx_firmware_allowlist.write_text("[]")

    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "generate-ita-policy.py"),
        "--measurements-dir", str(measurements_dir),
        "--cvm-artifacts-dir", str(cvm_artifacts_dir),
        "--template", str(template_path),
        "--nonce", nonce,
        "--output", str(output_path),
        "--temporary-gcp-tdx-firmware-allowlist",
        str(temporary_gcp_tdx_firmware_allowlist),
    ]

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )


class TestPolicyStructure:
    """Verify the generated policy has the correct tdx_h100_pp_image shape."""

    def test_single_match_entry_point(
        self, artifacts_dir, template_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        result = run_generate_script(artifacts_dir, template_path, output)
        assert result.returncode == 0, f"Script failed: {result.stderr}"

        policy = output.read_text()
        assert policy.count("match if {") == 1
        assert "matches_tdx" in policy
        assert "matches_nvgpu" in policy

    def test_matches_tdx_blocks_per_model(
        self, artifacts_dir, template_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        assert policy.count("matches_tdx if {") == 2
        assert "# Model: command-r-plus" in policy
        assert "# Model: aya-expanse" in policy

    def test_nvgpu_rules_preserved(
        self, artifacts_dir, template_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        assert "nvgpu_base_checks if {" in policy
        assert policy.count("matches_nvgpu if {") == 2
        assert "x-nvidia-gpu-driver-version" in policy

    def test_nvgpu_gcp_mismatch_workaround_is_narrow(
        self, artifacts_dir, template_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        assert 'input.nvgpu["x-nvidia-overall-att-result"] == false' in policy
        assert "count(input.nvgpu.claim_details) == 1" in policy
        assert 'count(records) == 1' in policy
        assert 'record.index == 9' in policy
        assert 'record.measurementSource == "Firmware"' in policy
        assert 'record.goldenSize == 48' in policy
        assert 'record.runtimeSize == 48' in policy
        assert 'record.goldenValue == "4b3ed0f834d10fef' in policy
        assert 'record.runtimeValue == "c80a9b62ce0d4118' in policy
        assert "x-nvidia-mismatch-indexes" not in policy

    def test_tdx_base_checks_in_template(
        self, artifacts_dir, template_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        assert policy.count("tdx_base_checks if {") == 1
        assert "tcb_level_acceptable" in policy
        assert "tdx.tdx_is_debuggable == false" in policy
        assert "tdx.tdx_seamsvn >= 271" in policy

    def test_matches_tdx_references_base_checks(
        self, artifacts_dir, template_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        import re
        blocks = re.findall(r'matches_tdx if \{.*?\}', policy, re.DOTALL)
        assert len(blocks) == 2
        for block in blocks:
            assert "tdx_base_checks" in block


class TestTdxBlockContent:
    """Verify the content of generated matches_tdx blocks."""

    def test_dynamic_measurements_present(
        self, artifacts_dir, template_path, tmp_path, real_measurements
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        assert real_measurements["mrtd"] in policy
        assert "1" * 96 in policy  # aya-expanse mrtd

    def test_temporary_gcp_firmware_allowlist_preserves_model_rtmrs(
        self, tmp_path, template_path, real_measurements
    ):
        meas_dir = tmp_path / "meas"
        model_dir = meas_dir / "cmp-l"
        model_dir.mkdir(parents=True)
        (model_dir / "measurements.json").write_text(json.dumps(real_measurements))

        firmware_allowlist = tmp_path / "temporary-firmware-allowlist.json"
        firmware_allowlist.write_text(json.dumps([
            {
                "name": "gcp-a3-new-firmware",
                "mrtd": "9bf86e6280ec4282b8b5822d8166410a456cdb720109aa799f0011fa63df1de3ee5e35e293fc410c061433163acb03a6",
                "rtmr0": "cacdba001f7732b60c1a60cac95e361717574cc4e1b13056cec49059d3229b3ea41381d00566b320318577ef74f91c4e",
            }
        ]))

        output = tmp_path / "policy.rego"
        result = run_generate_script(
            meas_dir,
            template_path,
            output,
            temporary_gcp_tdx_firmware_allowlist=firmware_allowlist,
        )

        assert result.returncode == 0, result.stderr
        policy = output.read_text()
        assert policy.count("matches_tdx if {") == 2
        assert (
            "# Model: cmp-l (TEMPORARY GCP firmware allowlist: "
            "gcp-a3-new-firmware)" in policy
        )
        assert "9bf86e6280ec4282b8b5822d8166410a456cdb720109aa799f0011fa63df1de3ee5e35e293fc410c061433163acb03a6" in policy
        assert "cacdba001f7732b60c1a60cac95e361717574cc4e1b13056cec49059d3229b3ea41381d00566b320318577ef74f91c4e" in policy
        assert policy.count(real_measurements["rtmr1"]) == 2
        assert policy.count(real_measurements["rtmr2"]) == 2
        assert policy.count(real_measurements["rtmr3"]) == 2

    def test_static_ref_vals_in_base_checks(
        self, artifacts_dir, template_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        for field in ["tdx_mrsignerseam", "tdx_mrconfigid", "tdx_mrowner",
                      "tdx_mrownerconfig", "tdx_seam_attributes",
                      "tdx_td_attributes"]:
            assert policy.count(f"tdx.{field} ==") == 1, (
                f"Expected {field} exactly once (in tdx_base_checks)"
            )

        assert "tdx.tdx_mrseam ==" not in policy
        assert "tdx.tdx_tee_tcb_svn ==" not in policy
        assert policy.count("tdx.tdx_seamsvn >= 271") == 1

    def test_debuggable_check_in_base_checks(
        self, artifacts_dir, template_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        assert policy.count("tdx_is_debuggable == false") == 1

    def test_all_rtmrs_present(
        self, artifacts_dir, template_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        for register in ["tdx_mrtd", "tdx_rtmr0", "tdx_rtmr1", "tdx_rtmr2", "tdx_rtmr3"]:
            assert policy.count(register) >= 2, (
                f"Expected {register} to appear at least twice (once per model)"
            )

    def test_rtmr3_omitted_when_missing(
        self, tmp_path, template_path, real_measurements
    ):
        meas_dir = tmp_path / "meas"
        model_dir = meas_dir / "no-rtmr3-model"
        model_dir.mkdir(parents=True)

        meas = {k: v for k, v in real_measurements.items() if k != "rtmr3"}
        (model_dir / "measurements.json").write_text(json.dumps(meas))

        output = tmp_path / "policy.rego"
        result = run_generate_script(meas_dir, template_path, output)

        assert result.returncode == 0
        policy = output.read_text()
        assert "tdx_rtmr3" not in policy

    def test_hex_values_are_96_chars(
        self, artifacts_dir, template_path, tmp_path
    ):
        import re
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        hex_values = re.findall(r'tdx\.tdx_mrtd == "([a-f0-9]+)"', policy)
        hex_values += re.findall(r'tdx\.tdx_rtmr\d == "([a-f0-9]+)"', policy)
        for val in hex_values:
            assert len(val) == 96, f"Expected 96-char hex, got {len(val)}: {val[:20]}..."


class TestPolicyNonce:
    """Verify the nonce rule keeps every upload unique for ITA dedup."""

    def test_nonce_rule_present(
        self, artifacts_dir, template_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(
            artifacts_dir, template_path, output,
            nonce="99999",
        )
        policy = output.read_text()
        assert 'integritee_nonce := "99999"' in policy

    def test_different_nonces_produce_different_policies(
        self, artifacts_dir, template_path, tmp_path
    ):
        out_a = tmp_path / "policy_a.rego"
        out_b = tmp_path / "policy_b.rego"

        run_generate_script(
            artifacts_dir, template_path, out_a,
            nonce="run-1",
        )
        run_generate_script(
            artifacts_dir, template_path, out_b,
            nonce="run-2",
        )
        assert out_a.read_text() != out_b.read_text()

    def test_same_nonce_produces_identical_policies(
        self, artifacts_dir, template_path, tmp_path
    ):
        out_1 = tmp_path / "policy_1.rego"
        out_2 = tmp_path / "policy_2.rego"

        run_generate_script(
            artifacts_dir, template_path, out_1,
            nonce="same-nonce",
        )
        run_generate_script(
            artifacts_dir, template_path, out_2,
            nonce="same-nonce",
        )
        assert out_1.read_text() == out_2.read_text()


class TestEdgeCases:
    """Test error handling and edge cases."""

    def test_single_model(
        self, tmp_path, template_path, real_measurements
    ):
        meas_dir = tmp_path / "meas"
        model_dir = meas_dir / "single-model"
        model_dir.mkdir(parents=True)
        (model_dir / "measurements.json").write_text(json.dumps(real_measurements))

        output = tmp_path / "policy.rego"
        result = run_generate_script(meas_dir, template_path, output)

        assert result.returncode == 0
        policy = output.read_text()
        assert policy.count("matches_tdx if {") == 1
        assert "# Model: single-model" in policy

    def test_no_models_fails(self, tmp_path, template_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        output = tmp_path / "policy.rego"
        result = run_generate_script(empty_dir, template_path, output)

        assert result.returncode != 0
        assert "No measurement files found" in result.stderr

    def test_skips_non_directory_entries(
        self, tmp_path, template_path, real_measurements
    ):
        meas_dir = tmp_path / "meas"
        meas_dir.mkdir()
        (meas_dir / "stray_file.json").write_text("{}")

        model_dir = meas_dir / "my-model"
        model_dir.mkdir()
        (model_dir / "measurements.json").write_text(json.dumps(real_measurements))

        output = tmp_path / "policy.rego"
        result = run_generate_script(meas_dir, template_path, output)

        assert result.returncode == 0
        policy = output.read_text()
        assert policy.count("matches_tdx if {") == 1

    def test_output_directory_created_if_missing(
        self, artifacts_dir, template_path, tmp_path
    ):
        output = tmp_path / "nested" / "deep" / "policy.rego"
        result = run_generate_script(artifacts_dir, template_path, output)

        assert result.returncode == 0
        assert output.exists()

    def test_missing_placeholder_in_template_fails(
        self, artifacts_dir, tmp_path
    ):
        bad_template = tmp_path / "bad-template.rego"
        bad_template.write_text("import rego.v1\ndefault match := false\n")

        output = tmp_path / "policy.rego"
        result = run_generate_script(artifacts_dir, bad_template, output)

        assert result.returncode != 0
        assert "${TDX_MATCH_BLOCKS}" in result.stderr
