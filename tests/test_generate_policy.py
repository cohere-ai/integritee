"""Tests for the generate-policy action.

Covers artifact fetching (firmware, versioned TDX baselines), initdata
measurement, and Rego policy rendering.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ACTION_ROOT = REPO_ROOT / ".github" / "actions" / "generate-policy"
OPA = shutil.which("opa")
sys.path.insert(0, str(ACTION_ROOT))


@pytest.fixture(scope="session")
def opa() -> str:
    """The opa binary, required rather than optional.

    Compiling and evaluating the generated policy is the coverage most worth
    having, so its absence fails instead of quietly reporting a green suite
    that never checked a policy at all.
    """
    if OPA is None:
        pytest.fail(
            "opa is not on PATH; install it from "
            "https://www.openpolicyagent.org/docs/#running-opa"
        )
    return OPA

# The schema of machine-types.yaml. Changing the table's structure means
# updating this set and the table; nothing else should need to name a field.
MACHINE_TYPE_FIELDS = {"platform", "tee", "ram_gib"}

from generate_policy import fetch  # noqa: E402
from generate_policy import generate  # noqa: E402
from generate_policy import ita  # noqa: E402
from generate_policy import measure  # noqa: E402

TEMPLATE = ita.TEMPLATE


def test_computes_rtmr3_directly_from_initdata():
    assert measure.compute_initdata_rtmr3(b"test") == (
        "e6c7526759cbdca9a11ba0bf7efe6d2193308532a85ba7e969889200de"
        "19583f4d3746983b22bf4638d571ec8aeabb85"
    )


def test_every_machine_type_declares_the_expected_fields():
    """Pin the schema of machine-types.yaml.

    An exact field match rejects a missing field, a stray one, and a typo like
    ram_gb, none of which the consuming code would notice until it read the
    entry.
    """
    table = generate.load_machine_types()
    assert table, "machine-types.yaml must not be empty"

    mismatched = {
        machine_type: sorted(set(entry) ^ MACHINE_TYPE_FIELDS)
        for machine_type, entry in table.items()
        if set(entry) != MACHINE_TYPE_FIELDS
    }
    assert not mismatched, (
        f"machine-types.yaml entries disagree with the expected schema "
        f"{sorted(MACHINE_TYPE_FIELDS)}: {mismatched}"
    )


def test_policy_template_uses_nras_v3_gpu_claims():
    policy = TEMPLATE.read_text()

    assert 'input.nvgpu["x-nvidia-overall-att-result"] == true' in policy
    assert "count(input.nvgpu.claim_details) > 0" in policy
    assert "every gpu_key in object.keys(input.nvgpu.claim_details)" in policy
    assert 'gpu["x-nvidia-gpu-attestation-report-cert-chain"]' in policy
    assert 'gpu["x-nvidia-gpu-driver-rim-cert-chain"]' in policy
    assert 'gpu["x-nvidia-gpu-vbios-rim-cert-chain"]' in policy


def test_nras_v3_gcp_mismatch_workaround_is_narrow():
    policy = TEMPLATE.read_text()

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


def test_github_api_errors_include_response_details(monkeypatch):
    monkeypatch.setattr(
        fetch.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            1,
            stdout="",
            stderr="gh: API rate limit exceeded (HTTP 403)",
        ),
    )

    with pytest.raises(RuntimeError, match="API rate limit exceeded"):
        fetch._gh_api("/repos/owner/repo/contents/file")


def test_firmware_cache_is_verified(tmp_path, monkeypatch):
    firmware = b"expected firmware"
    digest = hashlib.sha384(firmware).hexdigest()
    destination = tmp_path / "firmware.fd"
    destination.write_bytes(b"wrong firmware")
    run = Mock()
    monkeypatch.setattr(fetch.subprocess, "run", run)

    with pytest.raises(ValueError, match="firmware hash mismatch"):
        fetch.fetch_firmware(digest, destination)

    assert not destination.exists()
    run.assert_not_called()


def test_firmware_download_is_timed_verified_and_atomic(tmp_path, monkeypatch):
    firmware = b"expected firmware"
    digest = hashlib.sha384(firmware).hexdigest()
    destination = tmp_path / "firmware.fd"
    calls = []

    def fake_run(args, *, check):
        calls.append((args, check))
        Path(args[args.index("-o") + 1]).write_bytes(firmware)

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)

    fetch.fetch_firmware(digest, destination)

    assert destination.read_bytes() == firmware
    args, check = calls[0]
    assert check is True
    assert args[args.index("--connect-timeout") + 1] == "10"
    assert args[args.index("--max-time") + 1] == "120"
    assert args[args.index("-o") + 1] != str(destination)


def test_fetches_all_firmware_and_event_versions(monkeypatch):
    repo = "cohere-ai/cohere-cc-baselines"
    machine = "a3-highgpu-1g"
    firmware_a = "a" * 96
    firmware_f = "f" * 96
    responses = {
        f"/repos/{repo}/contents/baselines/gcp/tdx/defaults.json":
            _contents({
                machine: {
                    "firmware_sha384": firmware_a,
                    "version": "v2",
                },
            }),
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
            "machine_type": machine,
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
        (firmware_a, "v2"),
        (firmware_a, "v1"),
        (firmware_f, "v1"),
    ]
    assert all("/versions/" in variant["baseline_ref"] for variant in variants)


def test_falls_back_to_legacy_canonical_when_defaults_are_absent(monkeypatch):
    repo = "cohere-ai/cohere-cc-baselines"
    machine = "a3-highgpu-1g"
    firmware = "a" * 96

    def fake_run(cmd, **kwargs):
        if cmd[2].endswith(("/defaults.json", "/versions")):
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


def test_matches_legacy_canonical_to_identical_version(monkeypatch):
    repo = "cohere-ai/cohere-cc-baselines"
    machine = "a3-highgpu-1g"
    firmware = "a" * 96
    baseline = {
        "machine_type": machine,
        "firmware_sha384": firmware,
        "events": [{"rtmr": 0, "label": "event"}],
    }
    responses = {
        f"/repos/{repo}/contents/baselines/gcp/tdx/{machine}.json":
            _contents(baseline),
        f"/repos/{repo}/contents/baselines/gcp/tdx/versions": [
            {"type": "dir", "name": firmware},
        ],
        f"/repos/{repo}/contents/baselines/gcp/tdx/versions/{firmware}": [
            {"type": "dir", "name": "v1"},
        ],
        (
            f"/repos/{repo}/contents/baselines/gcp/tdx/versions/"
            f"{firmware}/v1/{machine}.json"
        ): _contents(baseline),
    }

    def fake_run(cmd, **kwargs):
        if cmd[2].endswith("/defaults.json"):
            return subprocess.CompletedProcess(
                cmd,
                1,
                stdout="",
                stderr="gh: Not Found (HTTP 404)",
            )
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=json.dumps(responses[cmd[2]]),
            stderr="",
        )

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)

    variants = fetch.fetch_baseline_variants(repo, machine)

    assert len(variants) == 1
    assert variants[0]["version"] == "v1"
    assert variants[0]["baseline"] == baseline


def test_render_policy_emits_unique_baseline_blocks_by_model(tmp_path):
    measurements_v1 = {
        "mrtd": "a" * 96,
        "rtmr0": "b" * 96,
        "rtmr1": "c" * 96,
        "rtmr2": "d" * 96,
        "rtmr3": "e" * 96,
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

    ita.render_policy(
        [target],
        ["580.159.04"],
        output,
    )

    policy = output.read_text()
    assert policy.count("matches_tdx if {") == 1
    assert policy.count("matches_tdx_platform if {") == 2
    assert policy.count("matches_tdx_workload if {") == 1
    assert "# Platform baseline: 111111111111/v1" in policy
    assert "# Platform baseline: 111111111111/v2" in policy
    assert "# Platform baseline: 111111111111/v3" not in policy
    assert "# Model: cmp-l (Initdata: unknown)" in policy
    assert 'accepted_gpu_driver_versions[gpu["x-nvidia-gpu-driver-version"]]' in policy
    assert '        "580.159.04"\n' in policy
    assert ita.EMPTY_POLICY_HEADER not in policy

    injected_version = '580.159.04"\n}\ndefault match := true\n#'
    ita.render_policy(
        [target],
        [injected_version],
        output,
    )
    policy = output.read_text()
    assert f"        {json.dumps(injected_version)}\n" in policy
    assert "\ndefault match := true\n" not in policy


def test_rendered_policy_keeps_static_platform_identity_in_base_checks(tmp_path):
    # PLATFORM_FIELDS excludes rtmr3, which the workload block requires.
    measurements = {
        field: "a" * 96
        for field in ita.PLATFORM_FIELDS
    }
    measurements["rtmr3"] = "b" * 96
    target = {
        "model": "cmp-l",
        "measurements": measurements,
        "baseline_variants": [
            {
                "version": "v1",
                "firmware_sha384": "1" * 96,
                "measurements": measurements,
            },
        ],
    }
    output = tmp_path / "policy.rego"

    ita.render_policy(
        [target],
        ["580.159.04"],
        output,
    )
    policy = output.read_text()

    assert policy.count("tdx_base_checks if {") == 1
    assert "tcb_level_not_revoked" in policy
    assert "tdx.tdx_is_debuggable == false" in policy
    assert "tdx.tdx_seamsvn >= 271" in policy

    # Fields constant across every target belong to tdx_base_checks alone. A
    # second occurrence means a generated per-target block re-asserted one,
    # which silently makes it a per-target value instead.
    for field in (
        "tdx_mrsignerseam",
        "tdx_mrconfigid",
        "tdx_mrowner",
        "tdx_mrownerconfig",
        "tdx_seam_attributes",
        "tdx_td_attributes",
    ):
        assert policy.count(f"tdx.{field} ==") == 1, field

    # Pinning either of these would break on any TDX module update.
    assert "tdx.tdx_mrseam ==" not in policy
    assert "tdx.tdx_tee_tcb_svn ==" not in policy


def _unsupported_machine_type() -> str:
    """A machine type ITA cannot appraise, taken from the table itself."""
    return next(
        machine_type
        for machine_type, entry in generate.load_machine_types().items()
        if entry["tee"] not in ita.SUPPORTED_TEES
    )


def _tdx_target() -> dict:
    measurements = {field: "a" * 96 for field in ita.PLATFORM_FIELDS}
    measurements["rtmr3"] = "b" * 96
    return {
        "model": "cmp-l",
        "measurements": measurements,
        "baseline_variants": [{
            "version": "v1",
            "firmware_sha384": "1" * 96,
            "measurements": measurements,
        }],
    }


def test_renders_an_inert_policy_when_nothing_matched(tmp_path, capsys):
    output = tmp_path / "policy.rego"

    ita.render_policy([], [], output)

    policy = output.read_text()
    # Every generated section is absent, so only the defaults define these.
    assert "matches_tdx_platform if {" not in policy
    assert "matches_tdx_workload if {" not in policy
    assert "default matches_tdx_platform := false" in policy
    assert "default matches_tdx_workload := false" in policy
    # An empty set, not a fabricated version no GPU can report.
    assert "accepted_gpu_driver_versions := {}" in policy
    assert '""' not in policy

    assert ita.EMPTY_POLICY_HEADER in policy
    assert "::warning::" in capsys.readouterr().out


def _render_module(tmp_path: Path, targets: list[dict]) -> Path:
    """Render a policy and wrap it in a package for opa to load standalone.

    ITA supplies the package declaration, so the uploaded file carries none.
    """
    policy = tmp_path / "policy.rego"
    ita.render_policy(
        targets,
        ["580.159.04"] if targets else [],
        policy,
    )
    module = tmp_path / "module.rego"
    module.write_text("package integritee\n\n" + policy.read_text())
    return module


@pytest.mark.parametrize(
    "targets",
    [[], [_tdx_target()]],
    ids=["zero-targets", "one-target"],
)
def test_rendered_policy_compiles(tmp_path, opa, targets):
    """A section substituted to nothing leaves its name undefined, which Rego
    rejects as an unsafe variable rather than a policy that denies. This is the
    check that the template's defaults hold that off.
    """
    result = subprocess.run(
        [opa, "check", str(_render_module(tmp_path, targets))],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def _opa_eval(
    opa: str,
    module: Path,
    query: str,
    input_file: Path | None = None,
):
    """Evaluate a query, returning None where the rule is undefined."""
    command = [opa, "eval", "--data", str(module), query]
    if input_file:
        command += ["--input", str(input_file)]
    result = subprocess.run(command, capture_output=True, text=True, check=True)

    entries = json.loads(result.stdout).get("result")
    if not entries:
        return None
    return entries[0]["expressions"][0]["value"]


def test_policy_with_no_targets_denies(tmp_path, opa):
    """Loading is not the property that matters; denying is.

    With no generated blocks there is no input that can satisfy the platform or
    workload rules, so the defaults must resolve them to false and carry that
    through to match.
    """
    document = _opa_eval(opa, _render_module(tmp_path, []), "data.integritee")

    assert document["matches_tdx_platform"] is False
    assert document["matches_tdx_workload"] is False
    assert document["match"] is False


def _accepting_nvgpu_input(tmp_path: Path, driver: str) -> Path:
    """Claims satisfying every NRAS check, leaving the driver the only variable."""
    valid = {"x-nvidia-cert-status": "valid"}
    flags = [
        "x-nvidia-gpu-attestation-report-nonce-match",
        "x-nvidia-gpu-arch-check",
        "x-nvidia-gpu-attestation-report-parsed",
        "x-nvidia-gpu-attestation-report-signature-verified",
        "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
    ] + [
        f"x-nvidia-gpu-{kind}-rim-{state}"
        for kind in ("driver", "vbios")
        for state in (
            "fetched",
            "measurements-available",
            "schema-validated",
            "signature-verified",
            "version-match",
        )
    ]
    gpu = {flag: True for flag in flags}
    gpu.update({
        "hwmodel": "GH100",
        "secboot": True,
        "measres": "success",
        "x-nvidia-gpu-driver-version": driver,
        "x-nvidia-gpu-attestation-report-cert-chain": valid,
        "x-nvidia-gpu-driver-rim-cert-chain": valid,
        "x-nvidia-gpu-vbios-rim-cert-chain": valid,
    })

    path = tmp_path / "input.json"
    path.write_text(json.dumps({
        "nvgpu": {
            "x-nvidia-overall-att-result": True,
            "claim_details": {"GPU-0": gpu},
        },
    }))
    return path


@pytest.mark.parametrize(
    "driver, accepted",
    [("580.159.04", True), ("999.99.99", False)],
)
def test_gpu_driver_version_must_be_one_the_policy_lists(
    tmp_path,
    opa,
    driver,
    accepted,
):
    """Set membership replaced a direct ==, so it has to enforce both ways.

    An unlisted version leaves the rule undefined rather than false, which
    fails the enclosing body just the same.
    """
    value = _opa_eval(
        opa,
        _render_module(tmp_path, [_tdx_target()]),
        "data.integritee.matches_nvgpu",
        _accepting_nvgpu_input(tmp_path, driver),
    )

    if accepted:
        assert value is True
    else:
        assert value is None


@pytest.mark.parametrize("missing_field", ita.PLATFORM_FIELDS)
def test_platform_match_requires_every_measurement(missing_field):
    measurements = {
        field: "a" * 96
        for field in ita.PLATFORM_FIELDS
    }
    del measurements[missing_field]

    with pytest.raises(
        ValueError,
        match=f"invalid or missing TDX measurement: {missing_field}",
    ):
        ita.generate_platform_match_block("baseline", measurements)


def test_measurement_values_cannot_inject_rego():
    injected = 'a' * 96 + '"\n}\ndefault match := true\n#'
    measurements = {
        field: "a" * 96
        for field in ita.PLATFORM_FIELDS
    }
    measurements["mrtd"] = injected

    with pytest.raises(ValueError, match="TDX measurement: mrtd"):
        ita.generate_platform_match_block("baseline", measurements)
    with pytest.raises(ValueError, match="TDX measurement: rtmr3"):
        ita.generate_workload_match_block("model", "initdata", injected)


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
    baseline_calls = []

    def fake_baseline_variants(repo, machine):
        baseline_calls.append((repo, machine))
        return variants

    monkeypatch.setattr(ita, "fetch_baseline_variants", fake_baseline_variants)
    firmware_calls = []
    monkeypatch.setattr(
        ita,
        "fetch_firmware",
        lambda *args: firmware_calls.append(args),
    )
    uki_calls = []
    monkeypatch.setattr(
        generate,
        "fetch_uki",
        lambda *args: uki_calls.append(args),
    )
    digest_calls = []

    def fake_oci_digest(ref):
        digest_calls.append(ref)
        return "sha256:123"

    monkeypatch.setattr(generate, "fetch_oci_digest", fake_oci_digest)
    monkeypatch.setattr(
        ita,
        "resolve_nvidia_driver_versions",
        lambda targets, artifacts: ["580.159.04"],
    )

    measurement_calls = []
    rtmr3_calls = []
    monkeypatch.setattr(
        ita,
        "compute_initdata_rtmr3",
        lambda initdata: rtmr3_calls.append(initdata) or "6" * 96,
    )
    baseline_hash_calls = []
    real_sha256 = hashlib.sha256

    def tracked_sha256(data):
        baseline_hash_calls.append(data)
        return real_sha256(data)

    monkeypatch.setattr(ita.hashlib, "sha256", tracked_sha256)

    def fake_measurements(*, baseline_path, output_dir, **kwargs):
        output_dir.mkdir(parents=True)
        (output_dir / "initdata.toml").write_text("test")
        version = baseline_path.stem
        measurement_calls.append(version)
        return {
            "mrtd": "1" * 96,
            "rtmr0": ("2" if version == "v1" else "3") * 96,
            "rtmr1": "4" * 96,
            "rtmr2": "5" * 96,
        }

    monkeypatch.setattr(ita, "compute_measurements", fake_measurements)

    manifest = tmp_path / "manifest.yaml"
    initdata = b"test"
    initdata_sha384 = hashlib.sha384(initdata).hexdigest()
    initdata_dir = tmp_path / "initdata"
    initdata_dir.mkdir()
    (initdata_dir / f"{initdata_sha384}.toml").write_bytes(initdata)
    second_initdata = b"other"
    second_sha384 = hashlib.sha384(second_initdata).hexdigest()
    (initdata_dir / f"{second_sha384}.toml").write_bytes(second_initdata)
    manifest.write_text(
        "targets:\n"
        "  - model: cmp-l\n"
        "    machine_type: a3-highgpu-1g\n"
        "    podvm_image_tag: image-tag\n"
        f"    initdata_file: initdata/{initdata_sha384}.toml\n"
        f"    initdata_sha384: {initdata_sha384}\n"
        "  - model: cmp-l-old\n"
        "    machine_type: a3-highgpu-1g\n"
        "    podvm_image_tag: image-tag\n"
        f"    initdata_file: initdata/{second_sha384}.toml\n"
        f"    initdata_sha384: {second_sha384}\n"
        "  - model: cmp-l-snp\n"
        f"    machine_type: {_unsupported_machine_type()}\n"
        "    podvm_image_tag: image-tag\n"
        f"    initdata_file: initdata/{initdata_sha384}.toml\n"
        f"    initdata_sha384: {initdata_sha384}\n"
    )
    predicate = tmp_path / "predicate.json"
    predicate.write_text("{}")
    policy = tmp_path / "policy.rego"

    generate.generate_policy(
        manifest_file=manifest,
        podvm_image="ghcr.io/owner/podvm",
        artifacts_dir=tmp_path / "artifacts",
        renderers=[ita.ItaRenderer(
            baselines_repo="owner/baselines",
            policy_output=policy,
        )],
        predicate_file=predicate,
    )

    predicate_targets = json.loads(predicate.read_text())["targets"]
    # The SNP target is dropped, and dropped before the baseline lookup below:
    # its machine type has no TDX baselines, so reaching that call would fail.
    assert [item["model"] for item in predicate_targets] == [
        "cmp-l",
        "cmp-l-old",
    ]
    target = predicate_targets[0]
    assert [item["version"] for item in target["baseline_variants"]] == [
        "v1",
        "v2",
    ]
    # The manifest carries no machine attributes; every field of the table
    # entry is resolved at generation time and must reach the signed predicate.
    machine = generate.load_machine_types()["a3-highgpu-1g"]
    assert {field: target[field] for field in machine} == machine
    assert baseline_calls == [
        ("owner/baselines", "a3-highgpu-1g"),
    ]
    assert len(baseline_hash_calls) == 2
    assert len(firmware_calls) == 1
    assert len(uki_calls) == 1
    assert digest_calls == ["ghcr.io/owner/podvm:image-tag"]
    assert rtmr3_calls == [initdata, second_initdata]
    assert measurement_calls == ["v1", "v2"]
    policy_text = policy.read_text()
    assert policy_text.count("matches_tdx if {") == 1
    assert policy_text.count("matches_tdx_platform if {") == 2
    assert policy_text.count("matches_tdx_workload if {") == 2
    assert "# Model: cmp-l (Initdata:" in policy_text
    assert "# Model: cmp-l-old (Initdata:" in policy_text


class _StubRenderer:
    """A renderer that records its targets instead of measuring them."""

    def __init__(self, name: str, tee: str | None, entry: dict):
        self.name = name
        self.tee = tee
        self.entry = entry
        self.seen: list[str] = []

    def cannot_appraise(self, machine: dict) -> str | None:
        if self.tee is None or machine["tee"] == self.tee:
            return None
        return f"{self.name} appraises {self.tee}, not {machine['tee']}"

    def render(self, targets, context) -> generate.RenderResult:
        self.seen = [resolved.target["model"] for resolved in targets]
        return generate.RenderResult(
            policy_files=[],
            predicate_targets={
                resolved.index: dict(self.entry) for resolved in targets
            },
        )


def test_each_renderer_sees_only_what_it_appraises(tmp_path, capsys):
    """The seam two attestation services meet at.

    Each renderer is handed its own subset, and a target appraised by more
    than one accumulates into a single predicate entry rather than appearing
    once per renderer.
    """
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "targets:\n"
        "  - model: cmp-l\n"
        "    machine_type: a3-highgpu-1g\n"
        "  - model: cmp-l-snp\n"
        f"    machine_type: {_unsupported_machine_type()}\n"
    )
    predicate = tmp_path / "predicate.json"
    tdx_only = _StubRenderer("tdx-only", "tdx", {"appraised_by_tdx": True})
    every_tee = _StubRenderer("every-tee", None, {"appraised_by_all": True})

    generate.generate_policy(
        manifest_file=manifest,
        podvm_image="ghcr.io/owner/podvm",
        artifacts_dir=tmp_path / "artifacts",
        renderers=[tdx_only, every_tee],
        predicate_file=predicate,
    )

    assert tdx_only.seen == ["cmp-l"]
    assert every_tee.seen == ["cmp-l", "cmp-l-snp"]
    # Manifest order, and one entry per target rather than per renderer.
    assert json.loads(predicate.read_text())["targets"] == [
        {"appraised_by_tdx": True, "appraised_by_all": True},
        {"appraised_by_all": True},
    ]
    assert (
        "::notice::Skipping cmp-l-snp: tdx-only appraises tdx"
        in capsys.readouterr().out
    )
