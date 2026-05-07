"""Tests for the merge-policy-inputs script.

Exercises Rego default-override merge and JSON deep-merge with
real-world-shaped data, edge cases, and the CLI interface.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT

MERGE_SCRIPT = REPO_ROOT / "scripts" / "merge-policy-inputs.py"

BASE_REGO = """\
package agent_policy

import rego.v1

default AddARPNeighborsRequest := false
default ExecProcessRequest := false
default CopyFileRequest := false
default CreateSandboxRequest := false
default DestroySandboxRequest := true
default WriteStreamRequest := false
"""

BASE_SETTINGS = {
    "pause_container": {"image": "registry.k8s.io/pause:3.9"},
    "cluster_config": {"default_namespace": "default"},
    "request_defaults": {
        "CreateContainerRequest": {
            "allow_env_regex": ["^HOSTNAME=", "^KUBERNETES_"]
        },
        "CopyFileRequest": {"regex": []},
        "ExecProcessRequest": {"regex": []},
    },
}


def run_merge(
    base_rules: str,
    base_settings: dict,
    model_dir: Path,
    output_dir: Path,
) -> subprocess.CompletedProcess:
    """Set up base files and run the merge script."""
    base_rules_path = output_dir / "base-rules.rego"
    base_settings_path = output_dir / "base-settings.json"
    base_rules_path.write_text(base_rules)
    base_settings_path.write_text(json.dumps(base_settings, indent=2))

    out = output_dir / "merged"
    return subprocess.run(
        [
            sys.executable, str(MERGE_SCRIPT),
            "--base-rules", str(base_rules_path),
            "--base-settings", str(base_settings_path),
            "--model-dir", str(model_dir),
            "--output-dir", str(out),
        ],
        capture_output=True,
        text=True,
    )


class TestRegoMerge:
    """Test Rego default-override merge semantics."""

    def test_override_replaces_base_default(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "rules.rego").write_text(
            "default ExecProcessRequest := true\n"
        )

        result = run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        assert result.returncode == 0, result.stderr

        merged = (tmp_path / "merged" / "merged-rules.rego").read_text()
        assert "default ExecProcessRequest := true" in merged
        assert "default ExecProcessRequest := false" not in merged

    def test_non_overridden_defaults_preserved(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "rules.rego").write_text(
            "default ExecProcessRequest := true\n"
        )

        result = run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = (tmp_path / "merged" / "merged-rules.rego").read_text()

        assert "default AddARPNeighborsRequest := false" in merged
        assert "default CopyFileRequest := false" in merged
        assert "default DestroySandboxRequest := true" in merged
        assert "default WriteStreamRequest := false" in merged

    def test_multiple_overrides(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "rules.rego").write_text(
            "default ExecProcessRequest := true\n"
            "default CopyFileRequest := true\n"
        )

        result = run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = (tmp_path / "merged" / "merged-rules.rego").read_text()

        assert "default ExecProcessRequest := true" in merged
        assert "default CopyFileRequest := true" in merged
        assert "default ExecProcessRequest := false" not in merged
        assert "default CopyFileRequest := false" not in merged

    def test_preamble_preserved(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "rules.rego").write_text(
            "default ExecProcessRequest := true\n"
        )

        result = run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = (tmp_path / "merged" / "merged-rules.rego").read_text()

        assert "package agent_policy" in merged
        assert "import rego.v1" in merged

    def test_extra_rules_appended(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "rules.rego").write_text(
            "default ExecProcessRequest := true\n"
            "\n"
            "ExecProcessRequest {\n"
            '    input.process.args[0] == "/bin/healthcheck"\n'
            "}\n"
        )

        result = run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = (tmp_path / "merged" / "merged-rules.rego").read_text()

        assert "default ExecProcessRequest := true" in merged
        assert '"/bin/healthcheck"' in merged
        assert "# --- Per-model rules ---" in merged

    def test_no_model_override_uses_base(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()

        result = run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = (tmp_path / "merged" / "merged-rules.rego").read_text()

        assert merged == BASE_REGO

    def test_override_order_matches_base(self, tmp_path: Path):
        """Overridden variables stay in the same position as the base."""
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "rules.rego").write_text(
            "default WriteStreamRequest := true\n"
        )

        result = run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = (tmp_path / "merged" / "merged-rules.rego").read_text()
        lines = merged.splitlines()

        default_lines = [l for l in lines if l.startswith("default ")]
        var_order = [l.split()[1] for l in default_lines]

        assert var_order.index("WriteStreamRequest") > var_order.index("DestroySandboxRequest")


class TestSettingsDeepMerge:
    """Test JSON deep-merge semantics."""

    def test_override_leaf_value(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "genpolicy-settings.json").write_text(json.dumps({
            "cluster_config": {"default_namespace": "production"}
        }))

        run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = json.loads((tmp_path / "merged" / "merged-settings.json").read_text())

        assert merged["cluster_config"]["default_namespace"] == "production"

    def test_non_overridden_keys_preserved(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "genpolicy-settings.json").write_text(json.dumps({
            "cluster_config": {"default_namespace": "production"}
        }))

        run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = json.loads((tmp_path / "merged" / "merged-settings.json").read_text())

        assert merged["pause_container"]["image"] == "registry.k8s.io/pause:3.9"
        assert "CreateContainerRequest" in merged["request_defaults"]

    def test_nested_override(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "genpolicy-settings.json").write_text(json.dumps({
            "request_defaults": {
                "ExecProcessRequest": {"regex": ["^/bin/sh$"]}
            }
        }))

        run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = json.loads((tmp_path / "merged" / "merged-settings.json").read_text())

        assert merged["request_defaults"]["ExecProcessRequest"]["regex"] == ["^/bin/sh$"]
        assert merged["request_defaults"]["CopyFileRequest"]["regex"] == []
        assert len(merged["request_defaults"]["CreateContainerRequest"]["allow_env_regex"]) == 2

    def test_array_replaced_not_appended(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "genpolicy-settings.json").write_text(json.dumps({
            "request_defaults": {
                "CreateContainerRequest": {
                    "allow_env_regex": ["^CUSTOM_VAR="]
                }
            }
        }))

        run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = json.loads((tmp_path / "merged" / "merged-settings.json").read_text())

        assert merged["request_defaults"]["CreateContainerRequest"]["allow_env_regex"] == ["^CUSTOM_VAR="]

    def test_add_new_key(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "genpolicy-settings.json").write_text(json.dumps({
            "custom_model_setting": {"gpu_count": 8}
        }))

        run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = json.loads((tmp_path / "merged" / "merged-settings.json").read_text())

        assert merged["custom_model_setting"]["gpu_count"] == 8
        assert merged["pause_container"]["image"] == "registry.k8s.io/pause:3.9"

    def test_no_model_settings_uses_base(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()

        run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        merged = json.loads((tmp_path / "merged" / "merged-settings.json").read_text())

        assert merged == BASE_SETTINGS


class TestCLIIntegration:
    """Test the merge script as a CLI tool."""

    def test_both_overrides_present(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "rules.rego").write_text("default ExecProcessRequest := true\n")
        (model_dir / "genpolicy-settings.json").write_text(json.dumps(
            {"cluster_config": {"default_namespace": "prod"}}
        ))

        result = run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        assert result.returncode == 0

        merged_rules = (tmp_path / "merged" / "merged-rules.rego").read_text()
        merged_settings = json.loads((tmp_path / "merged" / "merged-settings.json").read_text())

        assert "default ExecProcessRequest := true" in merged_rules
        assert merged_settings["cluster_config"]["default_namespace"] == "prod"

    def test_empty_model_dir(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()

        result = run_merge(BASE_REGO, BASE_SETTINGS, model_dir, tmp_path)
        assert result.returncode == 0
        assert "Using base rules (no model override)" in result.stdout
        assert "Using base settings (no model override)" in result.stdout

    def test_output_dir_created(self, tmp_path: Path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()

        out = tmp_path / "deep" / "nested" / "output"
        base_rules = tmp_path / "base.rego"
        base_settings = tmp_path / "base.json"
        base_rules.write_text(BASE_REGO)
        base_settings.write_text(json.dumps(BASE_SETTINGS))

        result = subprocess.run(
            [
                sys.executable, str(MERGE_SCRIPT),
                "--base-rules", str(base_rules),
                "--base-settings", str(base_settings),
                "--model-dir", str(model_dir),
                "--output-dir", str(out),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert (out / "merged-rules.rego").exists()
        assert (out / "merged-settings.json").exists()

    def test_real_repo_files(self, tmp_path: Path):
        """Run against the actual repo base files + command-r-plus overrides."""
        base_rules = REPO_ROOT / "rules" / "rules.rego"
        base_settings = REPO_ROOT / "rules" / "genpolicy-settings.json"
        model_dir = REPO_ROOT / "models" / "command-r-plus"
        out = tmp_path / "merged"

        result = subprocess.run(
            [
                sys.executable, str(MERGE_SCRIPT),
                "--base-rules", str(base_rules),
                "--base-settings", str(base_settings),
                "--model-dir", str(model_dir),
                "--output-dir", str(out),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

        merged_rules = (out / "merged-rules.rego").read_text()
        assert "default ExecProcessRequest := true" in merged_rules
        assert "default CopyFileRequest := true" in merged_rules
        assert "default AddARPNeighborsRequest := false" in merged_rules
        assert "package agent_policy" in merged_rules

        merged_settings = json.loads((out / "merged-settings.json").read_text())
        assert merged_settings["request_defaults"]["ExecProcessRequest"]["regex"] == [
            "^/bin/sh$", "^/usr/bin/python3$"
        ]
        assert merged_settings["pause_container"]["image"] == "registry.k8s.io/pause:3.9"

    def test_aya_expanse_no_overrides(self, tmp_path: Path):
        """aya-expanse has no overrides -- output should match base exactly."""
        base_rules = REPO_ROOT / "rules" / "rules.rego"
        base_settings = REPO_ROOT / "rules" / "genpolicy-settings.json"
        model_dir = REPO_ROOT / "models" / "aya-expanse"
        out = tmp_path / "merged"

        result = subprocess.run(
            [
                sys.executable, str(MERGE_SCRIPT),
                "--base-rules", str(base_rules),
                "--base-settings", str(base_settings),
                "--model-dir", str(model_dir),
                "--output-dir", str(out),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

        merged_rules = (out / "merged-rules.rego").read_text()
        assert merged_rules == base_rules.read_text()

        merged_settings = json.loads((out / "merged-settings.json").read_text())
        assert merged_settings == json.loads(base_settings.read_text())
