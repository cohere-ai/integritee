"""Tests that verify the repository structure matches the plan.

These tests ensure the repo scaffold is complete and all required
files are present with valid content.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from conftest import REPO_ROOT


class TestRepoStructure:
    """Verify the repository has all expected directories and files."""

    @pytest.mark.parametrize("path", [
        "models/command-r-plus/podspec.yaml",
        "models/command-r-plus/rules.rego",
        "models/command-r-plus/genpolicy-settings.json",
        "models/aya-expanse/podspec.yaml",
        "rules/rules.rego",
        "rules/genpolicy-settings.json",
        "attestation-policy/template.rego",
        ".github/workflows/attest-model.yaml",
        "scripts/generate-ita-policy.py",
        "scripts/build-predicate.py",
        "scripts/upload-ita-policy.sh",
        "scripts/validate-predicate.py",
        "scripts/fetch-genpolicy.sh",
        "scripts/merge-policy-inputs.py",
        "schemas/predicate-v1.schema.json",
        "schemas/predicate-v1.example.json",
        "clients/python/integritee/client.py",
        "clients/python/integritee/__init__.py",
        "clients/python/pyproject.toml",
        "README.md",
        "LICENSE",
        ".gitignore",
    ])
    def test_required_file_exists(self, path: str):
        assert (REPO_ROOT / path).exists(), f"Missing required file: {path}"


class TestPodspecValidity:
    """Verify model podspecs are valid Kubernetes manifests."""

    @pytest.mark.parametrize("model", ["command-r-plus", "aya-expanse"])
    def test_podspec_is_valid_yaml(self, model: str):
        path = REPO_ROOT / "models" / model / "podspec.yaml"
        doc = yaml.safe_load(path.read_text())
        assert doc is not None

    @pytest.mark.parametrize("model", ["command-r-plus", "aya-expanse"])
    def test_podspec_uses_kata_remote(self, model: str):
        path = REPO_ROOT / "models" / model / "podspec.yaml"
        doc = yaml.safe_load(path.read_text())
        runtime = doc["spec"]["template"]["spec"]["runtimeClassName"]
        assert runtime == "kata-remote"

    @pytest.mark.parametrize("model", ["command-r-plus", "aya-expanse"])
    def test_podspec_has_container(self, model: str):
        path = REPO_ROOT / "models" / model / "podspec.yaml"
        doc = yaml.safe_load(path.read_text())
        containers = doc["spec"]["template"]["spec"]["containers"]
        assert len(containers) >= 1

    @pytest.mark.parametrize("model", ["command-r-plus", "aya-expanse"])
    def test_podspec_has_kata_annotations(self, model: str):
        path = REPO_ROOT / "models" / model / "podspec.yaml"
        doc = yaml.safe_load(path.read_text())
        annotations = doc["spec"]["template"]["metadata"]["annotations"]
        assert "io.katacontainers.config.hypervisor.machine_type" in annotations

    @pytest.mark.parametrize("model", ["command-r-plus", "aya-expanse"])
    def test_podspec_has_cc_label(self, model: str):
        path = REPO_ROOT / "models" / model / "podspec.yaml"
        doc = yaml.safe_load(path.read_text())
        labels = doc["spec"]["template"]["metadata"]["labels"]
        assert labels.get("cohere.com/confidential-compute") == "true"


class TestGenpolicySettings:
    """Verify genpolicy settings are valid JSON."""

    def test_base_settings_valid(self):
        path = REPO_ROOT / "rules" / "genpolicy-settings.json"
        data = json.loads(path.read_text())
        assert "pause_container" in data

    def test_base_settings_has_env_regex(self):
        path = REPO_ROOT / "rules" / "genpolicy-settings.json"
        data = json.loads(path.read_text())
        env_regex = (
            data.get("request_defaults", {})
            .get("CreateContainerRequest", {})
            .get("allow_env_regex", [])
        )
        assert len(env_regex) > 0


class TestSchemaValidity:
    """Verify the JSON schema is valid and has expected structure."""

    def test_schema_is_valid_json(self, schema_path: Path):
        schema = json.loads(schema_path.read_text())
        assert schema["$id"] == "https://cohere.com/attestation-policy-ledger/v1"

    def test_schema_requires_all_fields(self, schema_path: Path):
        schema = json.loads(schema_path.read_text())
        required = schema["required"]
        for field in [
            "model_path", "event_type", "timestamp", "release_version",
            "measurements", "policy_id", "rego_policy_hash", "initdata_hash",
            "previous_rekor_log_index", "tool_versions", "source_artifacts",
        ]:
            assert field in required, f"Missing required field: {field}"

    def test_schema_measurements_pattern(self, schema_path: Path):
        schema = json.loads(schema_path.read_text())
        mrtd = schema["properties"]["measurements"]["properties"]["mrtd"]
        assert mrtd["pattern"] == "^[a-f0-9]{96}$"

    def test_schema_event_types(self, schema_path: Path):
        schema = json.loads(schema_path.read_text())
        event_enum = schema["properties"]["event_type"]["enum"]
        assert "policy_activated" in event_enum
        assert "policy_deprecated" in event_enum
        assert "policy_revoked" in event_enum


class TestWorkflowValidity:
    """Verify the GitHub Actions workflow is valid YAML with expected structure."""

    def test_workflow_is_valid_yaml(self):
        path = REPO_ROOT / ".github" / "workflows" / "attest-model.yaml"
        doc = yaml.safe_load(path.read_text())
        assert doc is not None

    def test_workflow_trigger_is_dispatch(self):
        path = REPO_ROOT / ".github" / "workflows" / "attest-model.yaml"
        doc = yaml.safe_load(path.read_text())
        # YAML parses `on:` as boolean True; access via True key
        trigger = doc.get("on") or doc.get(True)
        assert trigger is not None
        assert "workflow_dispatch" in trigger

    def test_workflow_has_version_input(self):
        path = REPO_ROOT / ".github" / "workflows" / "attest-model.yaml"
        doc = yaml.safe_load(path.read_text())
        trigger = doc.get("on") or doc.get(True)
        inputs = trigger["workflow_dispatch"]["inputs"]
        assert "version" in inputs
        assert inputs["version"]["required"] is True

    def test_workflow_has_required_permissions(self):
        path = REPO_ROOT / ".github" / "workflows" / "attest-model.yaml"
        doc = yaml.safe_load(path.read_text())
        perms = doc["permissions"]
        assert perms.get("id-token") == "write"
        assert perms.get("contents") == "write"
        assert perms.get("attestations") == "write"

    def test_workflow_has_cosign_install(self):
        path = REPO_ROOT / ".github" / "workflows" / "attest-model.yaml"
        content = path.read_text()
        assert "sigstore/cosign-installer" in content

    def test_workflow_has_attest_step(self):
        path = REPO_ROOT / ".github" / "workflows" / "attest-model.yaml"
        content = path.read_text()
        assert "cosign attest-blob" in content

    def test_workflow_has_release_creation(self):
        path = REPO_ROOT / ".github" / "workflows" / "attest-model.yaml"
        content = path.read_text()
        assert "gh release create" in content
