"""Tests for the predicate builder script.

Exercises scripts/build-predicate.py with real data and validates
output against the JSON schema.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from conftest import REPO_ROOT, make_cvm_artifacts_dir


def run_build_predicate(
    artifacts_dir: Path,
    cvm_artifacts_dir: Path,
    policy_id: str = "e34efa4e-9dde-4c6b-994f-0e95d3bce4ce",
    version: str = "v0.0.1",
    genpolicy_version: str = "3.12.0",
    cvm_measure_version: str = "0.3.0",
    previous_log_index: int = 0,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "build-predicate.py"),
            "--artifacts-dir", str(artifacts_dir),
            "--cvm-artifacts-dir", str(cvm_artifacts_dir),
            "--policy-id", policy_id,
            "--version", version,
            "--genpolicy-version", genpolicy_version,
            "--cvm-measure-version", cvm_measure_version,
            "--previous-log-index", str(previous_log_index),
        ],
        capture_output=True,
        text=True,
    )


class TestPredicateBuilder:
    """Test the predicate builder script."""

    def test_generates_predicates_for_all_models(self, artifacts_dir: Path, cvm_artifacts_dir: Path):
        result = run_build_predicate(artifacts_dir, cvm_artifacts_dir)
        assert result.returncode == 0, f"Script failed: {result.stderr}"

        for model in ["command-r-plus", "aya-expanse"]:
            pred_file = artifacts_dir / model / "predicate.json"
            assert pred_file.exists(), f"Missing predicate for {model}"

    def test_predicate_has_correct_model_path(self, artifacts_dir: Path, cvm_artifacts_dir: Path):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir)

        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())
        assert pred["model_path"] == "command-r-plus"

        pred = json.loads((artifacts_dir / "aya-expanse" / "predicate.json").read_text())
        assert pred["model_path"] == "aya-expanse"

    def test_predicate_contains_measurements(self, artifacts_dir: Path, cvm_artifacts_dir: Path, real_measurements: dict):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir)
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        assert pred["measurements"]["mrtd"] == real_measurements["mrtd"]
        assert pred["measurements"]["rtmr0"] == real_measurements["rtmr0"]
        assert pred["measurements"]["rtmr3"] == real_measurements["rtmr3"]

    def test_predicate_contains_policy_id(self, artifacts_dir: Path, cvm_artifacts_dir: Path):
        policy_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        run_build_predicate(artifacts_dir, cvm_artifacts_dir, policy_id=policy_id)
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        assert pred["policy_id"] == policy_id

    def test_predicate_contains_tool_versions(self, artifacts_dir: Path, cvm_artifacts_dir: Path):
        run_build_predicate(
            artifacts_dir,
            cvm_artifacts_dir,
            genpolicy_version="4.0.0",
            cvm_measure_version="1.2.3",
        )
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        assert pred["tool_versions"]["genpolicy"] == "4.0.0"
        assert pred["tool_versions"]["cvm_measure"] == "1.2.3"

    def test_predicate_contains_source_artifacts(self, artifacts_dir: Path, tmp_path: Path):
        cvm_dir = make_cvm_artifacts_dir(tmp_path, overrides={
            "command-r-plus": {"firmware_ref": "fw-v2", "uki_ref": "uki-v3", "baseline_ref": "bl-commit-xyz"},
            "aya-expanse": {"firmware_ref": "fw-v2", "uki_ref": "uki-v3", "baseline_ref": "bl-commit-xyz"},
        })
        run_build_predicate(artifacts_dir, cvm_dir)
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        assert pred["source_artifacts"]["firmware_ref"] == "fw-v2"
        assert pred["source_artifacts"]["uki_ref"] == "uki-v3"
        assert pred["source_artifacts"]["baseline_ref"] == "bl-commit-xyz"

    def test_predicate_chain_linking(self, artifacts_dir: Path, cvm_artifacts_dir: Path):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir, previous_log_index=42)
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        assert pred["previous_rekor_log_index"] == 42

    def test_genesis_entry_has_zero_previous(self, artifacts_dir: Path, cvm_artifacts_dir: Path):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir, previous_log_index=0)
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        assert pred["previous_rekor_log_index"] == 0

    def test_predicate_has_rego_hash(self, artifacts_dir: Path, cvm_artifacts_dir: Path):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir)
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        assert len(pred["rego_policy_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in pred["rego_policy_hash"])

    def test_predicate_has_initdata_hash(self, artifacts_dir: Path, cvm_artifacts_dir: Path):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir)
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        assert len(pred["initdata_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in pred["initdata_hash"])

    def test_predicate_has_iso_timestamp(self, artifacts_dir: Path, cvm_artifacts_dir: Path):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir)
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        from datetime import datetime
        ts = datetime.fromisoformat(pred["timestamp"])
        assert ts.tzinfo is not None, "Timestamp must be timezone-aware"

    def test_predicate_event_type_is_activated(self, artifacts_dir: Path, cvm_artifacts_dir: Path):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir)
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())
        assert pred["event_type"] == "policy_activated"

    def test_no_artifacts_fails(self, tmp_path: Path, cvm_artifacts_dir: Path):
        empty = tmp_path / "empty"
        empty.mkdir()
        result = run_build_predicate(empty, cvm_artifacts_dir)
        assert result.returncode != 0
        assert "No model artifacts found" in result.stderr


class TestPredicateSchemaValidation:
    """Validate generated predicates against the JSON schema."""

    def test_generated_predicate_validates_against_schema(
        self, artifacts_dir: Path, cvm_artifacts_dir: Path, schema_path: Path
    ):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir)
        schema = json.loads(schema_path.read_text())

        for model in ["command-r-plus", "aya-expanse"]:
            pred = json.loads((artifacts_dir / model / "predicate.json").read_text())
            jsonschema.validate(instance=pred, schema=schema)

    def test_example_predicate_validates(self, schema_path: Path):
        example = REPO_ROOT / "schemas" / "predicate-v1.example.json"
        schema = json.loads(schema_path.read_text())
        pred = json.loads(example.read_text())
        jsonschema.validate(instance=pred, schema=schema)

    def test_missing_required_field_fails_validation(self, schema_path: Path):
        schema = json.loads(schema_path.read_text())
        incomplete = {"model_path": "test"}

        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=incomplete, schema=schema)

    def test_invalid_measurement_length_fails(
        self, artifacts_dir: Path, cvm_artifacts_dir: Path, schema_path: Path
    ):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir)
        schema = json.loads(schema_path.read_text())
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        pred["measurements"]["mrtd"] = "tooshort"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=pred, schema=schema)

    def test_invalid_event_type_fails(
        self, artifacts_dir: Path, cvm_artifacts_dir: Path, schema_path: Path
    ):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir)
        schema = json.loads(schema_path.read_text())
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        pred["event_type"] = "invalid_event"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=pred, schema=schema)

    def test_negative_log_index_fails(
        self, artifacts_dir: Path, cvm_artifacts_dir: Path, schema_path: Path
    ):
        run_build_predicate(artifacts_dir, cvm_artifacts_dir)
        schema = json.loads(schema_path.read_text())
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        pred["previous_rekor_log_index"] = -1
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=pred, schema=schema)

    def test_extra_fields_rejected(
        self, artifacts_dir: Path, cvm_artifacts_dir: Path, schema_path: Path
    ):
        """Schema uses additionalProperties: false."""
        run_build_predicate(artifacts_dir, cvm_artifacts_dir)
        schema = json.loads(schema_path.read_text())
        pred = json.loads((artifacts_dir / "command-r-plus" / "predicate.json").read_text())

        pred["unexpected_field"] = "should fail"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=pred, schema=schema)
