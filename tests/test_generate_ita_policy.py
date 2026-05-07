"""Tests for the ITA attestation policy generator.

These tests exercise the actual script (scripts/generate-ita-policy.py)
with real measurement data and verify the generated Rego policy structure.
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
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "generate-ita-policy.py"),
            "--measurements-dir", str(measurements_dir),
            "--template", str(template_path),
            "--output", str(output_path),
        ],
        capture_output=True,
        text=True,
    )


class TestPolicyGeneration:
    """Test the complete ITA policy generation flow."""

    def test_generates_valid_rego_for_two_models(
        self, artifacts_dir: Path, template_path: Path, tmp_path: Path
    ):
        output = tmp_path / "policy.rego"
        result = run_generate_script(artifacts_dir, template_path, output)

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        assert output.exists()

        policy = output.read_text()
        assert "import rego.v1" in policy
        assert "default match := false" in policy

    def test_contains_both_model_blocks(
        self, artifacts_dir: Path, template_path: Path, tmp_path: Path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        assert "# Model: command-r-plus" in policy
        assert "# Model: aya-expanse" in policy

    def test_each_block_has_all_measurements(
        self, artifacts_dir: Path, template_path: Path, tmp_path: Path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        for register in ["tdx_mrtd", "tdx_rtmr0", "tdx_rtmr1", "tdx_rtmr2", "tdx_rtmr3"]:
            assert policy.count(register) == 2, (
                f"Expected {register} to appear twice (once per model)"
            )

    def test_debuggable_check_present(
        self, artifacts_dir: Path, template_path: Path, tmp_path: Path
    ):
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        assert policy.count("tdx_is_debuggable == false") == 2

    def test_measurement_values_are_correct(
        self, artifacts_dir: Path, template_path: Path, tmp_path: Path, real_measurements: dict
    ):
        """Verify the generated policy contains the exact measurement hex values."""
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        assert real_measurements["mrtd"] in policy
        assert "1" * 96 in policy  # aya-expanse MRTD

    def test_match_blocks_are_or_logic(
        self, artifacts_dir: Path, template_path: Path, tmp_path: Path
    ):
        """Each model gets a separate 'match if' block = logical OR."""
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        assert policy.count("match if {") == 2

    def test_single_model(self, tmp_path: Path, template_path: Path, real_measurements: dict):
        """Policy generation with only one model."""
        meas_dir = tmp_path / "meas"
        model_dir = meas_dir / "single-model"
        model_dir.mkdir(parents=True)
        (model_dir / "measurements.json").write_text(json.dumps(real_measurements))

        output = tmp_path / "policy.rego"
        result = run_generate_script(meas_dir, template_path, output)

        assert result.returncode == 0
        policy = output.read_text()
        assert policy.count("match if {") == 1
        assert "# Model: single-model" in policy

    def test_no_models_fails(self, tmp_path: Path, template_path: Path):
        """Empty measurements directory should exit with error."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        output = tmp_path / "policy.rego"
        result = run_generate_script(empty_dir, template_path, output)

        assert result.returncode != 0
        assert "No measurement files found" in result.stderr

    def test_skips_non_directory_entries(
        self, tmp_path: Path, template_path: Path, real_measurements: dict
    ):
        """Files at the top level of measurements-dir should be ignored."""
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
        assert policy.count("match if {") == 1

    def test_output_directory_created_if_missing(
        self, artifacts_dir: Path, template_path: Path, tmp_path: Path
    ):
        output = tmp_path / "nested" / "deep" / "policy.rego"
        result = run_generate_script(artifacts_dir, template_path, output)

        assert result.returncode == 0
        assert output.exists()

    def test_hex_values_are_96_chars(
        self, artifacts_dir: Path, template_path: Path, tmp_path: Path
    ):
        """All measurement hex strings in the policy should be exactly 96 chars."""
        output = tmp_path / "policy.rego"
        run_generate_script(artifacts_dir, template_path, output)
        policy = output.read_text()

        import re
        hex_values = re.findall(r'"([a-f0-9]{90,})"', policy)
        for val in hex_values:
            assert len(val) == 96, f"Expected 96-char hex, got {len(val)}: {val[:20]}..."
