"""End-to-end tests that simulate the full attestation pipeline locally.

Exercises the complete flow:
  measurements -> ITA policy generation -> predicate building -> schema validation

This is as close to a real run as possible without:
  - Actually running genpolicy (requires container images)
  - Actually calling ITA API (requires credentials)
  - Actually signing with Sigstore (requires OIDC token)
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

import yaml

from conftest import REPO_ROOT, REAL_MEASUREMENTS, STATIC_REF_VALS, make_cvm_artifacts_dir


def run_script(name: str, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / name), *args],
        capture_output=True,
        text=True,
    )


class TestEndToEndPipeline:
    """Simulate the full workflow pipeline from measurements to verified predicates."""

    @pytest.fixture
    def pipeline_dir(self, tmp_path: Path) -> Path:
        """Set up a complete pipeline directory mirroring the workflow artifacts."""
        models = {
            "command-r-plus": REAL_MEASUREMENTS,
            "aya-expanse": {
                "mrtd": "1" * 96,
                "rtmr0": "2" * 96,
                "rtmr1": "3" * 96,
                "rtmr2": "4" * 96,
                "rtmr3": "5" * 96,
            },
        }

        for model, measurements in models.items():
            d = tmp_path / model
            d.mkdir()
            (d / "measurements.json").write_text(json.dumps(measurements))
            (d / "kata-policy.rego").write_text(
                f"package agent_policy\n"
                f"import rego.v1\n"
                f"default CreateSandboxRequest := true\n"
                f"default DestroySandboxRequest := true\n"
            )
            (d / "initdata_b64.txt").write_text(
                "eyJhbGdvcml0aG0iOiJzaGEzODQiLCJkYXRhIjoiYWJjZGVmMTIzNDU2Nzg5MCJ9"
            )

        return tmp_path

    @pytest.fixture
    def ref_vals_path(self, tmp_path: Path) -> Path:
        p = tmp_path / "tdx-static-ref-vals.yaml"
        p.write_text(yaml.dump(STATIC_REF_VALS, default_flow_style=False))
        return p

    def test_full_pipeline(self, pipeline_dir: Path, ref_vals_path: Path, tmp_path: Path):
        """Run the complete pipeline: ITA policy gen -> predicate build -> validate."""
        policy_output = tmp_path / "ita-attestation-policy.rego"
        policy_id = "e34efa4e-9dde-4c6b-994f-0e95d3bce4ce"

        # Step 1: Generate ITA policy
        result = run_script("generate-ita-policy.py", [
            "--measurements-dir", str(pipeline_dir),
            "--template", str(REPO_ROOT / "attestation-policy" / "template.rego"),
            "--static-ref-vals", str(ref_vals_path),
            "--nonce", "e2e-test-run",
            "--output", str(policy_output),
        ])
        assert result.returncode == 0, f"ITA policy gen failed: {result.stderr}"
        assert policy_output.exists()

        policy_text = policy_output.read_text()
        assert "# Model: command-r-plus" in policy_text
        assert "# Model: aya-expanse" in policy_text
        assert policy_text.count("match if {") == 1
        assert policy_text.count("matches_tdx if {") == 2

        # Step 2: Build predicates
        cvm_dir = make_cvm_artifacts_dir(tmp_path, overrides={
            "command-r-plus": {"firmware_ref": "ovmf-2024-08", "uki_ref": "sha384:abc123def456", "baseline_ref": "cohere-cc-baselines@main"},
            "aya-expanse": {"firmware_ref": "ovmf-2024-08", "uki_ref": "sha384:abc123def456", "baseline_ref": "cohere-cc-baselines@main"},
        })
        result = run_script("build-predicate.py", [
            "--artifacts-dir", str(pipeline_dir),
            "--cvm-artifacts-dir", str(cvm_dir),
            "--policy-id", policy_id,
            "--version", "v0.0.1",
            "--genpolicy-version", "3.12.0",
            "--cvm-measure-version", "0.3.0",
            "--previous-log-index", "0",
        ])
        assert result.returncode == 0, f"Predicate build failed: {result.stderr}"

        # Step 3: Validate each predicate against schema
        schema = json.loads(
            (REPO_ROOT / "schemas" / "predicate-v1.schema.json").read_text()
        )

        for model in ["command-r-plus", "aya-expanse"]:
            pred_path = pipeline_dir / model / "predicate.json"
            assert pred_path.exists(), f"Missing predicate for {model}"

            pred = json.loads(pred_path.read_text())
            jsonschema.validate(instance=pred, schema=schema)

            assert pred["model_path"] == model
            assert pred["policy_id"] == policy_id
            assert pred["release_version"] == "v0.0.1"
            assert pred["previous_rekor_log_index"] == 0
            assert len(pred["measurements"]["mrtd"]) == 96

    def test_pipeline_preserves_measurement_integrity(self, pipeline_dir: Path, tmp_path: Path):
        """Measurements in the predicate must exactly match the input."""
        cvm_dir = make_cvm_artifacts_dir(tmp_path)
        run_script("build-predicate.py", [
            "--artifacts-dir", str(pipeline_dir),
            "--cvm-artifacts-dir", str(cvm_dir),
            "--policy-id", "00000000-0000-0000-0000-000000000000",
            "--version", "v0.0.1",
            "--genpolicy-version", "3.12.0",
            "--cvm-measure-version", "0.3.0",
            "--previous-log-index", "0",
        ])

        for model in ["command-r-plus", "aya-expanse"]:
            input_meas = json.loads(
                (pipeline_dir / model / "measurements.json").read_text()
            )
            pred = json.loads(
                (pipeline_dir / model / "predicate.json").read_text()
            )

            assert pred["measurements"] == input_meas, (
                f"Measurement mismatch for {model}"
            )

    def test_pipeline_different_policy_ids(self, pipeline_dir: Path, tmp_path: Path):
        """Running with different policy IDs produces different predicates."""
        cvm_dir = make_cvm_artifacts_dir(tmp_path)
        for pid in ["aaaa-bbbb", "cccc-dddd"]:
            run_script("build-predicate.py", [
                "--artifacts-dir", str(pipeline_dir),
                "--cvm-artifacts-dir", str(cvm_dir),
                "--policy-id", pid,
                "--version", "v0.0.1",
                "--genpolicy-version", "3.12.0",
                "--cvm-measure-version", "0.3.0",
                "--previous-log-index", "0",
            ])

        pred = json.loads(
            (pipeline_dir / "command-r-plus" / "predicate.json").read_text()
        )
        assert pred["policy_id"] == "cccc-dddd"

    def test_pipeline_chain_linking_across_releases(self, pipeline_dir: Path, tmp_path: Path):
        """Simulate two consecutive releases and verify chain linking."""
        cvm_dir = make_cvm_artifacts_dir(tmp_path)
        run_script("build-predicate.py", [
            "--artifacts-dir", str(pipeline_dir),
            "--cvm-artifacts-dir", str(cvm_dir),
            "--policy-id", "first-release",
            "--version", "v0.0.1",
            "--genpolicy-version", "3.12.0",
            "--cvm-measure-version", "0.3.0",
            "--previous-log-index", "0",
        ])

        pred_v1 = json.loads(
            (pipeline_dir / "command-r-plus" / "predicate.json").read_text()
        )
        assert pred_v1["previous_rekor_log_index"] == 0
        simulated_log_index_v1 = 12345

        run_script("build-predicate.py", [
            "--artifacts-dir", str(pipeline_dir),
            "--cvm-artifacts-dir", str(cvm_dir),
            "--policy-id", "second-release",
            "--version", "v0.0.2",
            "--genpolicy-version", "3.12.0",
            "--cvm-measure-version", "0.3.0",
            "--previous-log-index", str(simulated_log_index_v1),
        ])

        pred_v2 = json.loads(
            (pipeline_dir / "command-r-plus" / "predicate.json").read_text()
        )
        assert pred_v2["previous_rekor_log_index"] == simulated_log_index_v1

    def test_policy_rego_deterministic(self, pipeline_dir: Path, ref_vals_path: Path, tmp_path: Path):
        """Running ITA policy generation twice with same input produces same output."""
        out1 = tmp_path / "policy1.rego"
        out2 = tmp_path / "policy2.rego"
        template = str(REPO_ROOT / "attestation-policy" / "template.rego")
        ref_vals = str(ref_vals_path)

        run_script("generate-ita-policy.py", [
            "--measurements-dir", str(pipeline_dir),
            "--template", template,
            "--static-ref-vals", ref_vals,
            "--nonce", "determinism-test",
            "--output", str(out1),
        ])
        run_script("generate-ita-policy.py", [
            "--measurements-dir", str(pipeline_dir),
            "--template", template,
            "--static-ref-vals", ref_vals,
            "--nonce", "determinism-test",
            "--output", str(out2),
        ])

        assert out1.read_text() == out2.read_text()
