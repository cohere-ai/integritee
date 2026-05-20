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

from conftest import REPO_ROOT, STATIC_REF_VALS


def run_generate_script(
    measurements_dir: Path,
    template_path: Path,
    static_ref_vals_path: Path,
    output_path: Path,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "generate-ita-policy.py"),
            "--measurements-dir", str(measurements_dir),
            "--template", str(template_path),
            "--static-ref-vals", str(static_ref_vals_path),
            "--output", str(output_path),
        ],
        capture_output=True,
        text=True,
    )


class TestPolicyStructure:
    """Verify the generated policy has the correct tdx_h100_pp_image shape."""

    def test_single_match_entry_point(
        self, artifacts_dir, template_path, static_ref_vals_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        result = run_generate_script(artifacts_dir, template_path, static_ref_vals_path, output)
        assert result.returncode == 0, f"Script failed: {result.stderr}"

        policy = output.read_text()
        assert policy.count("match if {") == 1
        assert "matches_tdx" in policy
        assert "matches_nvgpu" in policy

    def test_matches_tdx_blocks_per_model(
        self, artifacts_dir, template_path, static_ref_vals_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, static_ref_vals_path, output)
        policy = output.read_text()

        assert policy.count("matches_tdx if {") == 2
        assert "# Model: command-r-plus" in policy
        assert "# Model: aya-expanse" in policy

    def test_nvgpu_rules_preserved(
        self, artifacts_dir, template_path, static_ref_vals_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, static_ref_vals_path, output)
        policy = output.read_text()

        assert "nvgpu_base_checks if {" in policy
        assert policy.count("matches_nvgpu if {") == 2
        assert "x-nvidia-gpu-driver-version" in policy


class TestTdxBlockContent:
    """Verify the content of generated matches_tdx blocks."""

    def test_dynamic_measurements_present(
        self, artifacts_dir, template_path, static_ref_vals_path, tmp_path, real_measurements
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, static_ref_vals_path, output)
        policy = output.read_text()

        assert real_measurements["mrtd"] in policy
        assert "1" * 96 in policy  # aya-expanse mrtd

    def test_static_ref_vals_in_each_block(
        self, artifacts_dir, template_path, static_ref_vals_path, tmp_path, static_ref_vals
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, static_ref_vals_path, output)
        policy = output.read_text()

        for field in ["tdx_mrseam", "tdx_mrsignerseam", "tdx_mrconfigid",
                       "tdx_mrowner", "tdx_mrownerconfig", "tdx_seam_attributes",
                       "tdx_td_attributes", "tdx_tee_tcb_svn"]:
            assert policy.count(f"tdx.{field} ==") == 2, (
                f"Expected {field} to appear twice (once per model)"
            )

        assert policy.count("tdx.tdx_seamsvn == 269") == 2

    def test_debuggable_check_in_each_block(
        self, artifacts_dir, template_path, static_ref_vals_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, static_ref_vals_path, output)
        policy = output.read_text()

        assert policy.count("tdx_is_debuggable == false") == 2

    def test_all_rtmrs_present(
        self, artifacts_dir, template_path, static_ref_vals_path, tmp_path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, static_ref_vals_path, output)
        policy = output.read_text()

        for register in ["tdx_mrtd", "tdx_rtmr0", "tdx_rtmr1", "tdx_rtmr2", "tdx_rtmr3"]:
            assert policy.count(register) >= 2, (
                f"Expected {register} to appear at least twice (once per model)"
            )

    def test_rtmr3_omitted_when_missing(
        self, tmp_path, template_path, static_ref_vals_path, real_measurements
    ):
        meas_dir = tmp_path / "meas"
        model_dir = meas_dir / "no-rtmr3-model"
        model_dir.mkdir(parents=True)

        meas = {k: v for k, v in real_measurements.items() if k != "rtmr3"}
        (model_dir / "measurements.json").write_text(json.dumps(meas))

        output = tmp_path / "policy.rego"
        result = run_generate_script(meas_dir, template_path, static_ref_vals_path, output)

        assert result.returncode == 0
        policy = output.read_text()
        assert "tdx_rtmr3" not in policy

    def test_hex_values_are_96_chars(
        self, artifacts_dir, template_path, static_ref_vals_path, tmp_path
    ):
        import re
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, static_ref_vals_path, output)
        policy = output.read_text()

        tdx_block_pattern = re.compile(r'matches_tdx if \{.*?\}', re.DOTALL)
        tdx_blocks = tdx_block_pattern.findall(policy)
        for block in tdx_blocks:
            hex_values = re.findall(r'tdx\.tdx_mr(?:td|seam|signerseam|configid|owner|ownerconfig) == "([a-f0-9]+)"', block)
            hex_values += re.findall(r'tdx\.tdx_rtmr\d == "([a-f0-9]+)"', block)
            for val in hex_values:
                assert len(val) == 96, f"Expected 96-char hex, got {len(val)}: {val[:20]}..."


class TestEdgeCases:
    """Test error handling and edge cases."""

    def test_single_model(
        self, tmp_path, template_path, static_ref_vals_path, real_measurements
    ):
        meas_dir = tmp_path / "meas"
        model_dir = meas_dir / "single-model"
        model_dir.mkdir(parents=True)
        (model_dir / "measurements.json").write_text(json.dumps(real_measurements))

        output = tmp_path / "policy.rego"
        result = run_generate_script(meas_dir, template_path, static_ref_vals_path, output)

        assert result.returncode == 0
        policy = output.read_text()
        assert policy.count("matches_tdx if {") == 1
        assert "# Model: single-model" in policy

    def test_no_models_fails(self, tmp_path, template_path, static_ref_vals_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        output = tmp_path / "policy.rego"
        result = run_generate_script(empty_dir, template_path, static_ref_vals_path, output)

        assert result.returncode != 0
        assert "No measurement files found" in result.stderr

    def test_skips_non_directory_entries(
        self, tmp_path, template_path, static_ref_vals_path, real_measurements
    ):
        meas_dir = tmp_path / "meas"
        meas_dir.mkdir()
        (meas_dir / "stray_file.json").write_text("{}")

        model_dir = meas_dir / "my-model"
        model_dir.mkdir()
        (model_dir / "measurements.json").write_text(json.dumps(real_measurements))

        output = tmp_path / "policy.rego"
        result = run_generate_script(meas_dir, template_path, static_ref_vals_path, output)

        assert result.returncode == 0
        policy = output.read_text()
        assert policy.count("matches_tdx if {") == 1

    def test_output_directory_created_if_missing(
        self, artifacts_dir, template_path, static_ref_vals_path, tmp_path
    ):
        output = tmp_path / "nested" / "deep" / "policy.rego"
        result = run_generate_script(artifacts_dir, template_path, static_ref_vals_path, output)

        assert result.returncode == 0
        assert output.exists()

    def test_missing_placeholder_in_template_fails(
        self, artifacts_dir, static_ref_vals_path, tmp_path
    ):
        bad_template = tmp_path / "bad-template.rego"
        bad_template.write_text("import rego.v1\ndefault match := false\n")

        output = tmp_path / "policy.rego"
        result = run_generate_script(artifacts_dir, bad_template, static_ref_vals_path, output)

        assert result.returncode != 0
        assert "${TDX_MATCH_BLOCKS}" in result.stderr
