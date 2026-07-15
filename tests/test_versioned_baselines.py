"""Tests for versioned TDX baseline discovery and policy rendering."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ACTION_ROOT = REPO_ROOT / ".github" / "actions" / "generate-policy"
sys.path.insert(0, str(ACTION_ROOT))

from generate_policy import fetch  # noqa: E402
from generate_policy import generate  # noqa: E402


def test_policy_template_uses_nras_v3_gpu_claims():
    policy = (
        ACTION_ROOT / "generate_policy" / "policy-template.rego"
    ).read_text()

    assert 'input.nvgpu["x-nvidia-overall-att-result"] == true' in policy
    assert "count(input.nvgpu.claim_details) > 0" in policy
    assert "every gpu_key in object.keys(input.nvgpu.claim_details)" in policy
    assert 'gpu["x-nvidia-gpu-attestation-report-cert-chain"]' in policy
    assert 'gpu["x-nvidia-gpu-driver-rim-cert-chain"]' in policy
    assert 'gpu["x-nvidia-gpu-vbios-rim-cert-chain"]' in policy


def test_nras_v3_gcp_mismatch_workaround_is_narrow():
    policy = (
        ACTION_ROOT / "generate_policy" / "policy-template.rego"
    ).read_text()

    assert 'input.nvgpu["x-nvidia-overall-att-result"] == false' in policy
    assert "count(input.nvgpu.claim_details) == 1" in policy
    assert "count(records) == 1" in policy
    assert "record.index == 9" in policy
    assert 'record.measurementSource == "Firmware"' in policy
    assert "record.goldenSize == 48" in policy
    assert "record.runtimeSize == 48" in policy
    assert 'record.goldenValue == "4b3ed0f834d10fef' in policy
    assert 'record.runtimeValue == "c80a9b62ce0d4118' in policy
    assert "x-nvidia-mismatch-indexes" not in policy
    assert policy.count("gpu.secboot == true") == 2


def _contents(value: dict) -> dict:
    encoded = base64.b64encode(json.dumps(value).encode()).decode()
    wrapped = "\n".join(
        encoded[index:index + 60]
        for index in range(0, len(encoded), 60)
    )
    return {"content": wrapped}


def test_fetches_all_firmware_and_event_versions(monkeypatch):
    repo = "cohere-ai/cohere-cc-baselines"
    machine = "a3-highgpu-1g"
    firmware_a = "a" * 96
    firmware_f = "f" * 96
    canonical = {"firmware_sha384": firmware_a, "events": []}
    responses = {
        f"/repos/{repo}/contents/baselines/gcp/tdx/{machine}.json":
            _contents(canonical),
        f"/repos/{repo}/contents/baselines/gcp/tdx/versions": [
            {"type": "dir", "name": firmware_f},
            {"type": "dir", "name": firmware_a},
        ],
        f"/repos/{repo}/contents/baselines/gcp/tdx/versions/{firmware_a}": [
            {"type": "dir", "name": "v2"},
            {"type": "dir", "name": "v1"},
        ],
        f"/repos/{repo}/contents/baselines/gcp/tdx/versions/{firmware_f}": [
            {"type": "dir", "name": "v1"},
        ],
    }
    for firmware, version in (
        (firmware_a, "v1"),
        (firmware_a, "v2"),
        (firmware_f, "v1"),
    ):
        path = (
            f"/repos/{repo}/contents/baselines/gcp/tdx/versions/"
            f"{firmware}/{version}/{machine}.json"
        )
        responses[path] = _contents({
            "firmware_sha384": firmware,
            "events": [{"rtmr": 0, "label": version}],
        })

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["gh", "api"]
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=json.dumps(responses[cmd[2]]),
            stderr="",
        )

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)

    variants = fetch.fetch_baseline_variants(repo, machine)

    assert [
        (variant["firmware_sha384"], variant["version"])
        for variant in variants
    ] == [
        (firmware_a, "v1"),
        (firmware_a, "v2"),
        (firmware_f, "v1"),
    ]
    assert all("/versions/" in variant["baseline_ref"] for variant in variants)


def test_falls_back_to_canonical_when_versions_are_absent(monkeypatch):
    repo = "cohere-ai/cohere-cc-baselines"
    machine = "a3-highgpu-1g"
    firmware = "a" * 96

    def fake_run(cmd, **kwargs):
        if cmd[2].endswith("/versions"):
            return subprocess.CompletedProcess(
                cmd,
                1,
                stdout="",
                stderr="gh: Not Found (HTTP 404)",
            )
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=json.dumps(_contents({
                "firmware_sha384": firmware,
                "events": [],
            })),
            stderr="",
        )

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)

    assert fetch.fetch_baseline_variants(repo, machine) == [{
        "version": "current",
        "firmware_sha384": firmware,
        "baseline": {"firmware_sha384": firmware, "events": []},
        "baseline_ref": (
            f"{repo}/baselines/gcp/tdx/{machine}.json"
        ),
    }]


def test_render_policy_groups_unique_baselines_by_model(tmp_path):
    measurements_v1 = {
        "mrtd": "a" * 96,
        "rtmr0": "b" * 96,
        "rtmr1": "c" * 96,
    }
    measurements_v2 = {
        **measurements_v1,
        "rtmr0": "d" * 96,
    }
    target = {
        "model": "cmp-l",
        "measurements": measurements_v1,
        "baseline_variants": [
            {
                "version": "v1",
                "firmware_sha384": "1" * 96,
                "measurements": measurements_v1,
            },
            {
                "version": "v2",
                "firmware_sha384": "1" * 96,
                "measurements": measurements_v2,
            },
            {
                "version": "v3",
                "firmware_sha384": "1" * 96,
                "measurements": measurements_v2,
            },
        ],
    }
    output = tmp_path / "policy.rego"

    generate.render_policy(
        [target],
        "580.159.04",
        ACTION_ROOT / "generate_policy" / "policy-template.rego",
        output,
    )

    policy = output.read_text()
    assert policy.count("matches_tdx if {") == 1
    assert '"cmp-l": [' in policy
    assert '"version": "111111111111.../v1"' in policy
    assert '"version": "111111111111.../v2"' in policy
    assert '"version": "111111111111.../v3"' not in policy


def test_generate_policy_measures_and_records_each_baseline(
    tmp_path,
    monkeypatch,
):
    firmware = "a" * 96
    variants = [
        {
            "version": version,
            "firmware_sha384": firmware,
            "baseline": {
                "firmware_sha384": firmware,
                "events": [{"rtmr": 0, "label": version}],
            },
            "baseline_ref": f"owner/baselines/versions/{firmware}/{version}/a3.json",
        }
        for version in ("v1", "v2")
    ]
    monkeypatch.setattr(
        generate,
        "fetch_baseline_variants",
        lambda repo, machine: variants,
    )
    monkeypatch.setattr(generate, "fetch_firmware", lambda *args: None)
    monkeypatch.setattr(generate, "fetch_uki", lambda *args: None)
    monkeypatch.setattr(generate, "fetch_oci_digest", lambda ref: "sha256:123")
    monkeypatch.setattr(
        generate,
        "resolve_nvidia_driver_version",
        lambda targets, artifacts: "580.159.04",
    )

    def fake_measurements(*, baseline_path, output_dir, **kwargs):
        output_dir.mkdir(parents=True)
        (output_dir / "initdata.toml").write_text("test")
        version = baseline_path.stem
        return {
            "mrtd": "1" * 96,
            "rtmr0": ("2" if version == "v1" else "3") * 96,
            "rtmr1": "4" * 96,
        }

    monkeypatch.setattr(generate, "compute_measurements", fake_measurements)

    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "targets:\n"
        "  - model: cmp-l\n"
        "    machine_type: a3-highgpu-1g\n"
        "    podvm_image_tag: image-tag\n"
        "    ram_gib: 234\n"
        "    initdata_b64: dGVzdA==\n"
    )
    predicate = tmp_path / "predicate.json"
    predicate.write_text("{}")
    policy = tmp_path / "policy.rego"

    generate.generate_policy(
        manifest_file=manifest,
        baselines_repo="owner/baselines",
        podvm_image="ghcr.io/owner/podvm",
        artifacts_dir=tmp_path / "artifacts",
        template_path=ACTION_ROOT / "generate_policy" / "policy-template.rego",
        policy_output=policy,
        predicate_file=predicate,
    )

    target = json.loads(predicate.read_text())["targets"][0]
    assert [item["version"] for item in target["baseline_variants"]] == [
        "v1",
        "v2",
    ]
    policy_text = policy.read_text()
    assert policy_text.count("matches_tdx if {") == 1
    assert policy_text.count('"version":') == 2
