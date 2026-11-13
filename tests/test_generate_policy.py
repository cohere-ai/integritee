"""Tests for the generate-policy action.

Covers artifact fetching (firmware, versioned TDX baselines), initdata
measurement, and Rego policy rendering.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ACTION_ROOT = REPO_ROOT / ".github" / "actions" / "generate-policy"
sys.path.insert(0, str(ACTION_ROOT))

# The schema of machine-types.yaml. Changing the table's structure means
# updating this set and the table; nothing else should need to name a field.
MACHINE_TYPE_FIELDS = {"platform", "tee", "ram_gib"}

from generate_policy import fetch  # noqa: E402
from generate_policy import generate  # noqa: E402
from generate_policy import ita  # noqa: E402
from generate_policy import manifest_contract  # noqa: E402
from generate_policy import measure  # noqa: E402

TEMPLATE = ita.TEMPLATE


def test_computes_rtmr3_directly_from_initdata():
    assert measure.compute_initdata_rtmr3(b"test") == (
        "e6c7526759cbdca9a11ba0bf7efe6d2193308532a85ba7e969889200de"
        "19583f4d3746983b22bf4638d571ec8aeabb85"
    )


def test_computes_pcr8_as_cvm_measure_does():
    assert measure.compute_initdata_pcr8(b'algorithm = "sha384"\n') == (
        "633c03ff85c6f3a62be58e87b3989cbb406c399b5e24093962e0e68d2def0a44"
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


def test_manifest_contract_v0_v1_boundary():
    assert manifest_contract.SCHEMA_VERSION == 1
    for version in (None, 2):
        with pytest.raises(ValueError, match="unsupported manifest schema_version"):
            manifest_contract.schema_version(
                {"schema_version": version, "targets": []}
            )
    with pytest.raises(ValueError, match="'sources' is a required property"):
        manifest_contract.manifest_targets(
            {"schema_version": 1, "targets": [{"model": "cmp-l"}]}
        )

    machine_types = manifest_contract.load_machine_types()
    legacy_target = {"machine_type": "a3-highgpu-1g"}

    assert manifest_contract.target_provider(
        legacy_target, machine_types, 0
    ) == "gcp"
    with pytest.raises(ValueError, match="provider is required"):
        manifest_contract.target_provider(
            legacy_target, machine_types, manifest_contract.SCHEMA_VERSION
        )
    with pytest.raises(ValueError, match="does not match"):
        manifest_contract.target_provider(
            {**legacy_target, "provider": "azure"},
            machine_types,
            manifest_contract.SCHEMA_VERSION,
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


def test_policy_template_uses_csp_rim_for_mrtd():
    """MRTD must be checked via the ITA CSP RIM catalog, not pinned values."""
    policy = TEMPLATE.read_text()

    assert "import data.public.intel.ita.tdxutils" in policy
    assert (
        "import data.public.google.gcp.tdx.rims.mrtd as gcpmrtds"
        in policy
    )
    assert "tdxutils.is_mrtd(input.tdx, gcpmrtds.measurements)" in policy
    assert "tdx.tdx_mrtd ==" not in policy
    assert "tdx.tdx_rtmr0 ==" not in policy


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


def test_render_rims_covers_every_baseline_variant(tmp_path):
    measurements_v1 = {
        "mrtd": "a" * 96,
        "rtmr0": "b" * 96,
        "rtmr1": "c" * 96,
        "rtmr2": "d" * 96,
        "rtmr3": "e" * 96,
    }
    measurements_v2 = {
        **measurements_v1,
        "rtmr1": "1" * 96,
    }
    target = {
        "model": "cmp-l",
        "added": "2026-10-21",
        "measurements": measurements_v1,
        "baseline_variants": [
            {"version": "v1", "measurements": measurements_v1},
            {"version": "v2", "measurements": measurements_v2},
            {"version": "v3", "measurements": measurements_v2},
        ],
    }

    names = ita.render_rims(
        [target],
        ["580.159.04", "570.1", "580.159.04"],
        "public.test",
        tmp_path / "packed",
        version="v0.0.23",
    )

    assert sorted(names) == [
        "public.test.platform", "public.test.release", "public.test.rtmr3.s000",
    ]
    assert ita.load_rims(tmp_path / "packed") == {
        "public.test.release": {"version": "v0.0.23"},
        "public.test.rtmr3.s000": {"rtmr3": ["e" * 96]},
        "public.test.platform": {
            "rtmr1_rtmr2": [
                {"rtmr1": "1" * 96, "rtmr2": "d" * 96},
                {"rtmr1": "c" * 96, "rtmr2": "d" * 96},
            ],
            "nvidia_driver_versions": ["570.1", "580.159.04"],
        },
    }


def test_rendered_policy_keeps_static_platform_identity_in_base_checks(tmp_path):
    output = tmp_path / "policy.rego"

    ita.render_policy(NAMESPACE, ["s000"], output)
    policy = output.read_text()

    assert policy.count("tdx_base_checks if {") == 1
    assert "tcb_level_not_revoked" in policy
    assert "tdx.tdx_is_debuggable == false" in policy
    assert "tdx.tdx_seamsvn >= 271" in policy

    # MRTD is verified via the ITA CSP RIM catalog in tdx_base_checks.
    assert policy.count("tdxutils.is_mrtd(input.tdx, gcpmrtds.measurements)") == 1
    assert "tdx.tdx_mrtd ==" not in policy
    assert "tdx.tdx_rtmr0 ==" not in policy

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
        if (entry["platform"], entry["tee"]) not in ita.SUPPORTED_PLATFORMS
    )


def _tdx_target() -> dict:
    measurements = {field: "a" * 96 for field in ita.PLATFORM_FIELDS}
    measurements["rtmr3"] = "b" * 96
    return {
        "model": "cmp-l",
        "added": "2026-10-21",
        "measurements": measurements,
        "baseline_variants": [{
            "version": "v1",
            "firmware_sha384": "1" * 96,
            "measurements": measurements,
        }],
    }


@pytest.mark.parametrize("nonce", [False, True])
def test_only_a_nonce_makes_identical_renders_differ(tmp_path, nonce):
    """ITA refuses a second policy with the same content: an unchanged policy
    has to render identically to be reused, and the nonce lets identical
    renders coexist."""
    first, second = tmp_path / "first.rego", tmp_path / "second.rego"
    ita.render_policy(NAMESPACE, ["s000"], first, nonce)
    ita.render_policy(NAMESPACE, ["s000"], second, nonce)

    assert (first.read_text() != second.read_text()) is nonce


@pytest.mark.parametrize(
    "name",
    [
        "public.test\nimport data.x",
        "public.1test",
        "a." * 10 + "a",
        "a" * 129,
    ],
)
def test_rim_names_follow_ita_rules(tmp_path, name):
    with pytest.raises(ValueError, match="invalid ITA RIM name"):
        ita.render_policy(name, ["s000"], tmp_path / "policy.rego")
    with pytest.raises(ValueError, match="invalid ITA RIM name"):
        ita.render_policy("public.test", [name], tmp_path / "policy.rego")


FIXTURES = Path(__file__).parent / "fixtures"

# ITA supplies data.public.intel.ita.tdxutils and the CSP RIM catalogs on the
# server only; loading them locally as a bundle lets opa check/eval exercise
# the rest of the policy.
RIM_STUBS = [FIXTURES / "ita-rim-stub.rego", FIXTURES / "gcp-mrtd-rims.json"]


NAMESPACE = "public.test"


def _render_module(
    tmp_path: Path,
    targets: list[dict],
    listed: list[str] | None = None,
    version: str = "",
) -> list[Path]:
    """Render a policy and its RIMs for opa to load standalone.

    The policy lists every rendered RTMR3 RIM unless listed names a subset.
    ITA supplies the package declaration, so the uploaded file carries none.
    """
    rim_dir = tmp_path / "rims"
    rim_names = ita.render_rims(
        targets,
        ["580.159.04"] if targets else [],
        NAMESPACE,
        rim_dir,
        version=version,
    )
    if listed is None:
        listed = ita.rtmr3_short_names(NAMESPACE, rim_names)

    policy = tmp_path / "policy.rego"
    ita.render_policy(NAMESPACE, listed, policy)
    module = tmp_path / "module.rego"
    module.write_text("package integritee\n\n" + policy.read_text())

    data = tmp_path / "rims.json"
    data.write_text(json.dumps(ita.rims_document(ita.load_rims(rim_dir))))
    return [module, data]


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
        [opa, "check", *RIM_STUBS, str(_render_module(tmp_path, targets)[0])],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def _opa_eval(
    opa: str,
    files: list[Path],
    query: str,
    input_file: Path | None = None,
):
    """Evaluate a query, returning None where the rule is undefined."""
    command = [opa, "eval"]
    for path in [*RIM_STUBS, *files]:
        command += ["--data", str(path)]
    command.append(query)
    if input_file:
        command += ["--input", str(input_file)]
    result = subprocess.run(command, capture_output=True, text=True, check=True)

    entries = json.loads(result.stdout).get("result")
    if not entries:
        return None
    return entries[0]["expressions"][0]["value"]


def test_policy_exports_the_release_version(tmp_path, opa):
    files = _render_module(tmp_path, [], version="v0.0.23")

    assert _opa_eval(opa, files, "data.integritee.exportOnMatch") == {
        "integritee_version": "v0.0.23"
    }


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
    valid = {"x-nvidia-cert-status": "valid", "x-nvidia-cert-ocsp-status": "good"}
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
        "dbgstat": "disabled",
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
    """The driver check reads the platform RIM, so it has to enforce both ways.

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


@pytest.mark.parametrize(
    "mutate",
    [
        {"dbgstat": "enabled"},
        {"x-nvidia-gpu-attestation-report-cert-chain": {
            "x-nvidia-cert-status": "valid",
            "x-nvidia-cert-ocsp-status": "revoked",
        }},
        {"x-nvidia-gpu-driver-rim-cert-chain": {
            "x-nvidia-cert-status": "valid",
            "x-nvidia-cert-ocsp-status": "revoked",
        }},
        {"x-nvidia-gpu-vbios-rim-cert-chain": {
            "x-nvidia-cert-status": "valid",
            "x-nvidia-cert-ocsp-status": "revoked",
        }},
    ],
    ids=["debug-enabled", "device-cert", "driver-rim-cert", "vbios-rim-cert"],
)
def test_gpu_debug_and_revocation_are_refused(tmp_path, opa, mutate):
    """A revoked signer passes x-nvidia-cert-status, so OCSP is what catches it.

    Both paths are covered: the mismatch fallback shares this rule, so neither
    can admit a device the primary path would refuse.
    """
    input_file = _accepting_nvgpu_input(tmp_path, "580.159.04")
    claims = json.loads(input_file.read_text())
    claims["nvgpu"]["claim_details"]["GPU-0"].update(mutate)
    input_file.write_text(json.dumps(claims))

    value = _opa_eval(
        opa,
        _render_module(tmp_path, [_tdx_target()]),
        "data.integritee.matches_nvgpu",
        input_file,
    )

    assert value is None


RTMR3_VALUES = [hashlib.sha384(str(i).encode()).hexdigest() for i in range(50)]


def _tdx_input(tmp_path: Path, rtmr1: str, rtmr2: str, rtmr3: str) -> Path:
    path = tmp_path / "input.json"
    path.write_text(json.dumps({
        "tdx": {"tdx_rtmr1": rtmr1, "tdx_rtmr2": rtmr2, "tdx_rtmr3": rtmr3},
    }))
    return path


def _two_platform_target() -> dict:
    """Two released pairs, (c, d) and (e, f), and RTMR3 values 0 to 9."""
    variants = [
        {"measurements": {"rtmr1": r1 * 96, "rtmr2": r2 * 96, "rtmr3": rtmr3}}
        for r1, r2 in (("c", "d"), ("e", "f"))
        for rtmr3 in RTMR3_VALUES[:10]
    ]
    return {
        "model": "cmp-l",
        "added": "2026-10-21",
        "measurements": {},
        "baseline_variants": variants,
    }


@pytest.mark.parametrize(
    "rtmr1, rtmr2, accepted",
    [("c", "d", True), ("e", "f", True), ("c", "f", False), ("e", "d", False)],
)
def test_platform_pair_is_matched_within_one_entry(
    tmp_path, opa, rtmr1, rtmr2, accepted
):
    """Each field of a mixed pair is released, but no entry has both."""
    value = _opa_eval(
        opa,
        _render_module(tmp_path, [_two_platform_target()]),
        "data.integritee.matches_tdx_platform",
        _tdx_input(tmp_path, rtmr1 * 96, rtmr2 * 96, RTMR3_VALUES[0]),
    )

    assert value is accepted


@pytest.mark.parametrize(
    "rtmr3, accepted",
    [(value, True) for value in RTMR3_VALUES[:10]]
    + [(RTMR3_VALUES[10], False)],
)
def test_workload_matches_a_value_in_any_rtmr3_rim(
    tmp_path, opa, monkeypatch, rtmr3, accepted
):
    monkeypatch.setattr(ita, "RTMR3_RIM_CAPACITY", 4)
    files = _render_module(tmp_path, [_two_platform_target()])

    value = _opa_eval(
        opa,
        files,
        "data.integritee.matches_tdx_workload",
        _tdx_input(tmp_path, "c" * 96, "d" * 96, rtmr3),
    )

    assert value is accepted


@pytest.mark.parametrize(
    "listed, accepted",
    [(["s000", "s001"], True), (["s001"], False), (["s000", "s099"], True)],
)
def test_only_listed_rtmr3_rims_are_read(
    tmp_path, opa, monkeypatch, listed, accepted
):
    """The prefix import exposes every RIM under it; the list bounds it."""
    monkeypatch.setattr(ita, "RTMR3_RIM_CAPACITY", 5)

    value = _opa_eval(
        opa,
        _render_module(tmp_path, [_two_platform_target()], listed=listed),
        "data.integritee.matches_tdx_workload",
        _tdx_input(tmp_path, "c" * 96, "d" * 96, RTMR3_VALUES[0]),
    )

    assert value is accepted


POLICY_ID = "3f2c1a9e-8b7d-4c6e-9a1f-0e2d3c4b5a69"
POLICY_HASH = "c29tZSBwb2xpY3kgaGFzaA=="
TOKEN_POLICY_HASH = base64.b64encode(POLICY_HASH.encode()).decode()


def _rp_token(**overrides) -> dict:
    gpu = {"x-nvidia-gpu-driver-version": "580.159.04"}
    return {
        "policy_ids_matched": [
            {"id": POLICY_ID, "version": "v1", "hash": TOKEN_POLICY_HASH},
        ],
        "tdx": {
            "tdx_rtmr1": "c" * 96,
            "tdx_rtmr2": "d" * 96,
            "tdx_rtmr3": RTMR3_VALUES[0],
        },
        "nvgpu": {"claim_details": {"GPU-0": gpu}},
        **overrides,
    }


@pytest.mark.parametrize(
    "token, accepted",
    [
        (_rp_token(), True),
        (_rp_token(policy_ids_matched=[{"id": POLICY_ID, "hash": POLICY_HASH}]),
         False),
        (_rp_token(policy_ids_matched=[
            {"id": "0" * 8 + POLICY_ID[8:], "hash": TOKEN_POLICY_HASH},
        ]), False),
        (_rp_token(tdx={**_rp_token()["tdx"], "tdx_rtmr2": "f" * 96}), False),
        (_rp_token(tdx={**_rp_token()["tdx"], "tdx_rtmr3": RTMR3_VALUES[10]}),
         False),
        (_rp_token(nvgpu={"claim_details": {}}), False),
        (_rp_token(nvgpu={"claim_details": {
            "GPU-0": {"x-nvidia-gpu-driver-version": "580.159.04"},
            "GPU-1": {"x-nvidia-gpu-driver-version": "999.99.99"},
        }}), False),
    ],
    ids=[
        "accepted",
        "other-hash",
        "other-policy",
        "mixed-pair",
        "unlisted-rtmr3",
        "no-gpu",
        "one-unlisted-driver",
    ],
)
def test_rp_policy_accepts_only_this_release(
    tmp_path, opa, monkeypatch, token, accepted
):
    monkeypatch.setattr(ita, "RTMR3_RIM_CAPACITY", 4)
    rim_dir = tmp_path / "rims"
    ita.render_rims(
        [_two_platform_target()], ["580.159.04"], NAMESPACE, rim_dir
    )
    policy = tmp_path / "rp.rego"
    ita.render_rp_policy(rim_dir, POLICY_ID, POLICY_HASH, policy)
    data = tmp_path / "rims.json"
    data.write_text(json.dumps(ita.rims_document(ita.load_rims(rim_dir))))
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps(token))

    value = _opa_eval(opa, [policy, data], "data.ita_rp.allow", token_file)

    assert value is accepted


@pytest.mark.parametrize(
    "policy_id, policy_hash",
    [(POLICY_ID + '"\nallow := true #', POLICY_HASH),
     (POLICY_ID, POLICY_HASH + '"\nallow := true #')],
)
def test_rp_policy_rejects_invalid_policy_identity(
    tmp_path, policy_id, policy_hash
):
    with pytest.raises(ValueError, match="invalid ITA policy"):
        ita.render_rp_policy(
            tmp_path, policy_id, policy_hash, tmp_path / "rp.rego"
        )


@pytest.mark.parametrize("missing_field", ita.PLATFORM_FIELDS)
def test_platform_rim_requires_every_measurement(missing_field):
    measurements = {
        field: "a" * 96
        for field in ita.PLATFORM_FIELDS
    }
    del measurements[missing_field]

    with pytest.raises(
        ValueError,
        match=f"invalid or missing TDX measurement: {missing_field}",
    ):
        ita.platform_rim([measurements], [])


def test_rtmr3s_are_placed_oldest_target_first(tmp_path, monkeypatch):
    monkeypatch.setattr(ita, "RTMR3_RIM_CAPACITY", 2)
    newer, older = _tdx_target(), _tdx_target()
    newer["added"], older["added"] = "2026-11-02", "2026-11-01"
    newer["measurements"] = {**newer["measurements"], "rtmr3": RTMR3_VALUES[0]}
    older["measurements"] = {**older["measurements"], "rtmr3": RTMR3_VALUES[1]}
    third = {**older, "measurements": {
        **older["measurements"], "rtmr3": RTMR3_VALUES[2],
    }}
    del third["added"]
    for target in (newer, older, third):
        del target["baseline_variants"]

    ita.render_rims([newer, older, third], [], NAMESPACE, tmp_path)

    rims = ita.load_rims(tmp_path)
    # An undated target counts as oldest; RIM content is sorted.
    assert rims[f"{NAMESPACE}.rtmr3.s000"] == {
        "rtmr3": sorted(RTMR3_VALUES[1:3])
    }
    assert rims[f"{NAMESPACE}.rtmr3.s001"] == {"rtmr3": [RTMR3_VALUES[0]]}


def test_rtmr3s_stay_in_the_last_release_rims(tmp_path, monkeypatch):
    monkeypatch.setattr(ita, "RTMR3_RIM_CAPACITY", 2)
    target = _tdx_target()
    del target["baseline_variants"]
    last_rims = {
        f"{NAMESPACE}.rtmr3.s000": {"rtmr3": [RTMR3_VALUES[1]]},
        f"{NAMESPACE}.rtmr3.s001": {"rtmr3": [target["measurements"]["rtmr3"]]},
        f"{NAMESPACE}.platform": {},
    }

    ita.render_rims([target], [], NAMESPACE, tmp_path, last_rims)

    rims = ita.load_rims(tmp_path)
    assert rims[f"{NAMESPACE}.rtmr3.s000"] == {"rtmr3": []}
    assert rims[f"{NAMESPACE}.rtmr3.s001"] == last_rims[f"{NAMESPACE}.rtmr3.s001"]


def _rtmr3_rims(**shards: str) -> dict[str, dict]:
    return {
        f"{NAMESPACE}.rtmr3.{name}": {"rtmr3": sorted(values)}
        for name, values in shards.items()
    }


def test_missing_rim_dir_fails(tmp_path):
    with pytest.raises(ValueError, match="RIM directory not found"):
        ita.load_rims(tmp_path / "missing")


def test_last_rtmr3_rims_come_back_out_of_the_rims_document():
    rtmr3_rims = _rtmr3_rims(s000="a", s001="b")
    document = ita.rims_document({
        **rtmr3_rims,
        f"{NAMESPACE}.platform": {"rtmr1_rtmr2": []},
    })

    assert document["public"]["test"]["rtmr3"]["s001"] == {"rtmr3": ["b"]}
    assert ita.last_rtmr3_rims(document, NAMESPACE) == rtmr3_rims
    assert ita.last_rtmr3_rims(document, "cohere_testing.r1_1") == {}

    document["public"]["test"]["rtmr3"]["zz"] = {"rtmr3": []}
    with pytest.raises(ValueError, match="unexpected RTMR3 RIM names"):
        ita.last_rtmr3_rims(document, NAMESPACE)


def test_rims_document_rejects_a_rim_nested_in_another():
    with pytest.raises(ValueError, match="prefix of another RIM"):
        ita.rims_document({"ns.a": {}, "ns.a.b": {}})


def test_rtmr3_values_stay_in_their_rim_across_releases(monkeypatch):
    monkeypatch.setattr(ita, "RTMR3_RIM_CAPACITY", 3)
    last = _rtmr3_rims(s000="abc", s001="def", s002="g")

    def update(values: str) -> dict[str, dict]:
        return ita.update_rtmr3_rims(last, list(values), NAMESPACE)

    # The RIM that lost b takes the first new value, the emptiest the next.
    assert update("acdefgxy") == _rtmr3_rims(s000="acx", s001="def", s002="gy")
    # An emptied middle RIM stays; an emptied last RIM goes.
    assert update("abcg") == _rtmr3_rims(s000="abc", s001="", s002="g")
    assert update("abcdef") == _rtmr3_rims(s000="abc", s001="def")
    # Without a last release, values pack in order.
    assert ita.update_rtmr3_rims({}, list("abcd"), NAMESPACE) == _rtmr3_rims(
        s000="abc", s001="d"
    )


def test_full_rtmr3_shard_fits_a_rim():
    shard = {"rtmr3": ["f" * 96] * ita.RTMR3_RIM_CAPACITY}

    assert len(ita.rim_bytes(shard)) <= ita.RIM_MAX_BYTES


def test_rtmr3_rims_reject_invalid_measurements(tmp_path):
    target = _tdx_target()
    del target["baseline_variants"]
    target["measurements"] = {**target["measurements"], "rtmr3": "A" * 96}

    with pytest.raises(ValueError, match="TDX measurement: rtmr3"):
        ita.render_rims([target], [], NAMESPACE, tmp_path)


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
            "rtmr1": ("4" if version == "v1" else "7") * 96,
            "rtmr2": "5" * 96,
        }

    monkeypatch.setattr(ita, "compute_tdx_measurements", fake_measurements)

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
        "    added: '2026-10-21'\n"
        "    machine_type: a3-highgpu-1g\n"
        "    podvm_image_tag: image-tag\n"
        f"    initdata_file: initdata/{initdata_sha384}.toml\n"
        f"    initdata_sha384: {initdata_sha384}\n"
        f"    sources: [{'b' * 40}]\n"
        "  - model: cmp-l-old\n"
        "    added: '2026-10-22'\n"
        "    machine_type: a3-highgpu-1g\n"
        "    podvm_image_tag: image-tag\n"
        f"    initdata_file: initdata/{second_sha384}.toml\n"
        f"    initdata_sha384: {second_sha384}\n"
        f"    sources: [{'b' * 40}]\n"
        "  - model: cmp-l-snp\n"
        f"    machine_type: {_unsupported_machine_type()}\n"
        "    podvm_image_tag: image-tag\n"
        f"    initdata_file: initdata/{initdata_sha384}.toml\n"
        f"    initdata_sha384: {initdata_sha384}\n"
        f"    sources: [{'b' * 40}]\n"
    )
    predicate = tmp_path / "predicate.json"
    predicate.write_text("{}")
    renderer = ita.ItaRenderer(
        baselines_repo="owner/baselines",
        output_dir=tmp_path / "policies",
        rim_namespace="cohere_testing.r1_1",
    )

    generate.generate_policy(
        manifest_file=manifest,
        podvm_image="ghcr.io/owner/podvm",
        artifacts_dir=tmp_path / "artifacts",
        renderers=[renderer],
        predicate_file=predicate,
    )

    policy = renderer.policy_file
    assert policy.name == "ita_policy.rego"
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
    rim_names = json.loads(predicate.read_text())["ita_rims"]
    assert rim_names == [
        "cohere_testing.r1_1.platform",
        "cohere_testing.r1_1.release",
        "cohere_testing.r1_1.rtmr3.s000",
    ]
    assert "import data.cohere_testing.r1_1.rtmr3 as" in policy.read_text()
    rtmr3_rim = renderer.rim_dir / "cohere_testing.r1_1.rtmr3.s000.json"
    assert json.loads(rtmr3_rim.read_text())["rtmr3"] == sorted(
        {item["measurements"]["rtmr3"] for item in predicate_targets}
    )
    rims_document = json.loads(renderer.rims_file.read_text())
    assert rims_document["cohere_testing"]["r1_1"]["rtmr3"]["s000"] == (
        json.loads(rtmr3_rim.read_text())
    )


@pytest.mark.parametrize(
    ("rim_namespace", "error"),
    [("", "is required"), ("cohere-testing.1", "invalid ITA RIM name")],
)
def test_ita_renderer_requires_a_valid_rim_namespace(
    tmp_path, rim_namespace, error
):
    renderer = ita.ItaRenderer(
        baselines_repo="owner/baselines",
        output_dir=tmp_path,
        rim_namespace=rim_namespace,
    )
    with pytest.raises(ValueError, match=error):
        renderer.render([], context=None)


class _StubRenderer:
    """A renderer that records its targets instead of measuring them."""

    def __init__(self, name: str, tee: str | None, output_dir: Path):
        self.name = name
        self.tee = tee
        self.output_dir = output_dir
        self.seen: list[str] = []
        self.considered_providers: list[str] = []

    @property
    def policy_files(self) -> list[Path]:
        return [self.output_dir / f"{self.name}.rego"]

    def cannot_appraise(self, provider: str, machine: dict) -> str | None:
        self.considered_providers.append(provider)
        if self.tee is None or machine["tee"] == self.tee:
            return None
        return f"{self.name} appraises {self.tee}, not {machine['tee']}"

    def render(self, targets, context) -> generate.RenderResult:
        self.seen = [resolved.target["model"] for resolved in targets]
        return generate.RenderResult(
            outputs={f"{self.name}-policy-file": str(self.policy_files[0])},
            predicate_targets={
                resolved.index: {f"appraised_by_{self.name}": True}
                for resolved in targets
            },
        )


def test_each_renderer_sees_only_what_it_appraises(
    tmp_path,
    monkeypatch,
    capsys,
):
    """The seam two attestation services meet at.

    Each renderer is handed its own subset, a target appraised by more than
    one accumulates into a single predicate entry rather than appearing once
    per renderer, and every path and count reaches the workflow.
    """
    digest = "a" * 96
    source = "b" * 40
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "schema_version: 1\n"
        "targets:\n"
        "  - model: cmp-l\n"
        "    provider: gcp\n"
        "    machine_type: a3-highgpu-1g\n"
        "    podvm_image_tag: test\n"
        f"    initdata_file: initdata/{digest}.toml\n"
        f"    initdata_sha384: {digest}\n"
        f"    sources: [{source}]\n"
        "  - model: cmp-l-snp\n"
        "    provider: azure\n"
        f"    machine_type: {_unsupported_machine_type()}\n"
        "    podvm_image_tag: test\n"
        f"    initdata_file: initdata/{digest}.toml\n"
        f"    initdata_sha384: {digest}\n"
        f"    sources: [{source}]\n"
    )
    predicate = tmp_path / "predicate.json"
    github_output = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    tdx = _StubRenderer("tdx", "tdx", tmp_path)
    every = _StubRenderer("every", None, tmp_path)

    generate.generate_policy(
        manifest_file=manifest,
        podvm_image="ghcr.io/owner/podvm",
        artifacts_dir=tmp_path / "artifacts",
        renderers=[tdx, every],
        predicate_file=predicate,
    )

    assert tdx.seen == ["cmp-l"]
    assert every.seen == ["cmp-l", "cmp-l-snp"]
    assert tdx.considered_providers == ["gcp", "azure"]
    assert every.considered_providers == ["gcp", "azure"]
    written = json.loads(predicate.read_text())
    # Manifest order, and one entry per target rather than per renderer.
    assert written["targets"] == [
        {"appraised_by_tdx": True, "appraised_by_every": True},
        {"appraised_by_every": True},
    ]
    assert written["target_counts"] == {"tdx": 1, "every": 2}
    assert github_output.read_text().splitlines() == [
        f"tdx-policy-file={tmp_path / 'tdx.rego'}",
        "tdx-target-count=1",
        f"every-policy-file={tmp_path / 'every.rego'}",
        "every-target-count=2",
    ]
    assert (
        "::notice::Skipping cmp-l-snp: tdx appraises tdx"
        in capsys.readouterr().out
    )


def test_a_run_covering_nothing_fails(tmp_path, capsys):
    """The one floor on target counts, and it spans every requested type.

    A single policy covering nothing is a legitimate revocation, so the run
    only fails when no requested type matched anything and no policy it
    produced could admit a node.
    """
    manifest = tmp_path / "manifest.yaml"
    digest = "a" * 96
    manifest.write_text(
        "targets:\n"
        "  - model: cmp-l-snp\n"
        f"    machine_type: {_unsupported_machine_type()}\n"
        "    podvm_image_tag: test\n"
        f"    initdata_file: initdata/{digest}.toml\n"
        f"    initdata_sha384: {digest}\n"
        f"    sources: [{'b' * 40}]\n"
    )

    with pytest.raises(SystemExit) as failure:
        generate.generate_policy(
            manifest_file=manifest,
            podvm_image="ghcr.io/owner/podvm",
            artifacts_dir=tmp_path / "artifacts",
            renderers=[_StubRenderer("tdx", "tdx", tmp_path)],
        )

    assert failure.value.code == 1
    assert "no manifest target matched any requested policy type" in (
        capsys.readouterr().err
    )


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("ita", ["ita"]),
        (" ita,trustee ", ["ita", "trustee"]),
        ("ita\ttrustee ita", ["ita", "trustee"]),
    ],
)
def test_policy_types_accepts_a_separated_list(raw, expected):
    assert generate.parse_policy_types(raw, {"ita", "trustee"}) == expected


@pytest.mark.parametrize("raw", ["", "   ", "ITA", "ita trustee-cpu"])
def test_policy_types_rejects_anything_it_cannot_generate(raw):
    """An empty or misspelled value must fail rather than emit nothing.

    Silently generating no policy is the failure mode this input exists to
    rule out, since a release would then ship without one.
    """
    with pytest.raises(ValueError, match="policy"):
        generate.parse_policy_types(raw, {"ita", "trustee"})


def test_stale_policies_are_cleared_before_a_run(tmp_path, capsys):
    """Including for a type this run was not asked to generate.

    A leftover file would otherwise be attested and released as current, so
    clearing covers every type the action can emit, not just the requested
    ones.
    """
    unrequested = _StubRenderer("trustee", None, tmp_path)
    stale = unrequested.policy_files[0]
    stale.write_text("# from a previous run\n")
    bystander = tmp_path / "predicate.json"
    bystander.write_text("{}")

    generate.clear_policies([unrequested])

    assert not stale.exists()
    assert bystander.exists()
    assert str(stale) in capsys.readouterr().out


def test_policy_output_dir_is_workspace_relative(monkeypatch):
    """Because the paths this action reports are used from the host.

    Inside the container the workspace is /github/workspace, a path that does
    not exist on the runner, so an absolute path here would be reported to
    steps that then cannot find the file it names.
    """
    monkeypatch.setenv("GITHUB_WORKSPACE", "/github/workspace")

    output_dir = generate.policy_output_dir()

    assert not output_dir.is_absolute()
    assert "github/workspace" not in str(output_dir)
