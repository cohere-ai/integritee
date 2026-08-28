"""Tests for the Trustee policy pair.

Centred on appraisal rather than on the shape of the templates: the policies
are evaluated against captured Azure SEV-SNP and remote NRAS claims, so a
test fails when the policy admits the wrong evidence rather than when someone
rewords a rule. Structural checks are kept to the two things evaluation
cannot see, injection and line length.

opa only ever runs on rendered output. A raw template holds bare ${...}
lines and is not valid Rego.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ACTION_ROOT = REPO_ROOT / ".github" / "actions" / "generate-policy"
FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(ACTION_ROOT))

from generate_policy import generate  # noqa: E402
from generate_policy import trustee  # noqa: E402

# Affirming values the CPU policy assigns when everything matches. rats-cert
# treats 2..=31 as affirming, so a denial shows up as the template's default.
AFFIRMING = {"executables": 3, "hardware": 2, "configuration": 2}
DENIED = {"executables": 33, "hardware": 97, "configuration": 36}


def _claims(name: str) -> dict:
    """Load a claims fixture as a verifier would emit it."""
    claims = json.loads((FIXTURES / name).read_text())
    claims.pop("_comment", None)
    return claims


def _pcrs(claims: dict) -> dict:
    """The cvm-measure output that produced a fixture's vTPM claims.

    Derived from the claims rather than written out again, so a rendered
    policy and the evidence it is tested against cannot drift apart. This is
    also the zero-padding mapping in reverse: pcr04 in the claim, pcr4 out of
    cvm-measure.
    """
    tpm = claims["az-snp-vtpm"]["tpm"]
    return {
        source: tpm[claim]
        for source, claim in {**trustee.IMAGE_PCRS, "pcr8": "pcr08"}.items()
    }


def _cpu_policy(
    tmp_path: Path,
    images: list[tuple[str, dict]],
    initdata: list[tuple[str, str]],
) -> Path:
    path = tmp_path / trustee.CPU_POLICY_FILE
    trustee.render_cpu_policy(
        [trustee.generate_image_block(tag, pcrs) for tag, pcrs in images],
        [
            trustee.generate_initdata_block(model, model[:12], pcr8)
            for model, pcr8 in initdata
        ],
        path,
    )
    return path


def _gpu_policy(tmp_path: Path, versions: list[str]) -> Path:
    path = tmp_path / trustee.GPU_POLICY_FILE
    trustee.render_gpu_policy(versions, path)
    return path


def _appraise(opa: str, policy: Path, claims: dict, tmp_path: Path) -> dict:
    """Evaluate trust_claims against one set of claims."""
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps(claims))
    result = subprocess.run(
        [
            opa, "eval", "--data", str(policy), "--input", str(input_file),
            "data.policy.trust_claims",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)["result"][0]["expressions"][0]["value"]


@pytest.fixture
def snp_claims() -> dict:
    return _claims("azure-snp-claims.json")


@pytest.fixture
def gpu_claims() -> dict:
    return _claims("nvidia-nras-claims.json")


@pytest.fixture
def cpu_policy(tmp_path, snp_claims) -> Path:
    pcrs = _pcrs(snp_claims)
    return _cpu_policy(
        tmp_path,
        [("release-image", pcrs)],
        [("cat2508rws-l", pcrs["pcr8"])],
    )


def test_cpu_policy_affirms_the_node_it_was_generated_from(
    opa,
    tmp_path,
    cpu_policy,
    snp_claims,
):
    """The load-bearing test: good evidence reaches an affirming appraisal.

    Also the check that every AR4SI claim TNG requires at startup is present,
    and that no ${PLACEHOLDER} survived, since neither would parse.
    """
    claims = _appraise(opa, cpu_policy, snp_claims, tmp_path)

    assert claims == {
        **AFFIRMING,
        "file-system": 0,
        "instance-identity": 0,
        "runtime-opaque": 0,
        "storage-opaque": 0,
        "sourced-data": 0,
    }


@pytest.mark.parametrize(
    "path, value, denied",
    [
        (["az-snp-vtpm", "tpm", "pcr04"], "0" * 64, "executables"),
        (["az-snp-vtpm", "tpm", "pcr05"], "0" * 64, "executables"),
        (["az-snp-vtpm", "tpm", "pcr09"], "0" * 64, "executables"),
        (["az-snp-vtpm", "tpm", "pcr11"], "0" * 64, "executables"),
        (["az-snp-vtpm", "measurement"], "A" * 64, "executables"),
        # Top level rather than under the attester, since transform_claims
        # lifts it there before the policy ever sees it.
        (["init_data"], "0" * 64, "configuration"),
        (["az-snp-vtpm", "policy_debug_allowed"], "true", "configuration"),
        (["az-snp-vtpm", "policy_migrate_ma"], "true", "configuration"),
        (["az-snp-vtpm", "platform_smt_enabled"], "true", "configuration"),
        (["az-snp-vtpm", "reported_tcb_snp"], "26", "hardware"),
    ],
)
def test_cpu_policy_denies_mutated_evidence(
    opa,
    tmp_path,
    cpu_policy,
    snp_claims,
    path,
    value,
    denied,
):
    """One mutation at a time, so each check is shown to carry its dimension."""
    mutated = copy.deepcopy(snp_claims)
    claim = mutated
    for key in path[:-1]:
        claim = claim[key]
    claim[path[-1]] = value

    appraised = _appraise(opa, cpu_policy, mutated, tmp_path)

    assert appraised[denied] == DENIED[denied]
    for dimension, affirming in AFFIRMING.items():
        if dimension != denied:
            assert appraised[dimension] == affirming


@pytest.mark.parametrize(
    "bootloader, affirms",
    [("10", True), ("11", True), ("9", False), ("2", False)],
)
def test_tcb_floors_compare_numerically(
    opa,
    tmp_path,
    cpu_policy,
    snp_claims,
    bootloader,
    affirms,
):
    """Without to_number these floors are vacuous, which fails open.

    Every claim is a string and Rego orders numbers before strings, so a bare
    `>= 10` holds for any string at all. "9" is the case that makes the
    difference visible: it fails numerically and passes lexically.
    """
    snp_claims["az-snp-vtpm"]["reported_tcb_bootloader"] = bootloader

    appraised = _appraise(opa, cpu_policy, snp_claims, tmp_path)

    assert (appraised["hardware"] == 2) is affirms


def test_a_disk_that_never_existed_is_rejected(opa, tmp_path, snp_claims):
    """Two images, and evidence mixing registers from both.

    The four image registers are measured from one disk.raw, so they are
    asserted in a single rule. Split into separate rules they would each be
    satisfiable independently and this combination would be admitted.
    """
    first = _pcrs(snp_claims)
    second = {name: "b" * 64 for name in first}
    policy = _cpu_policy(
        tmp_path,
        [("image-a", first), ("image-b", second)],
        [("cat2508rws-l", first["pcr8"])],
    )
    chimera = copy.deepcopy(snp_claims)
    chimera["az-snp-vtpm"]["tpm"]["pcr05"] = second["pcr5"]

    assert _appraise(opa, policy, snp_claims, tmp_path)["executables"] == 3
    assert _appraise(opa, policy, chimera, tmp_path)["executables"] == 33


def test_any_approved_image_pairs_with_any_approved_initdata(
    opa,
    tmp_path,
    snp_claims,
):
    """The one cross-product that is intended rather than tolerated.

    A model's initdata places no constraint on which approved image version
    the host runs, which is what turns N x M blocks into N + M.
    """
    pcrs = _pcrs(snp_claims)
    other_initdata = "c" * 64
    policy = _cpu_policy(
        tmp_path,
        [("image-a", pcrs), ("image-b", {name: "b" * 64 for name in pcrs})],
        [("cat2508rws-l", pcrs["pcr8"]), ("cmp-l", other_initdata)],
    )
    crossed = copy.deepcopy(snp_claims)
    crossed["init_data"] = other_initdata

    appraised = _appraise(opa, policy, crossed, tmp_path)

    assert appraised["executables"] == 3
    assert appraised["configuration"] == 2


@pytest.mark.parametrize(
    "driver, affirms",
    [("580.173.02", True), ("580.173.03", False)],
)
def test_gpu_policy_pins_the_driver_the_image_ships(
    opa,
    tmp_path,
    gpu_claims,
    driver,
    affirms,
):
    """No fallback tier, so a driver outside the set denies as it does on ITA."""
    policy = _gpu_policy(tmp_path, [driver])

    appraised = _appraise(opa, policy, gpu_claims, tmp_path)

    assert appraised["hardware"] == 2
    assert appraised["executables"] == 3
    assert (appraised["configuration"] == 2) is affirms


def test_gpu_policy_denies_a_debuggable_device(opa, tmp_path, gpu_claims):
    """A check ITA lacks, so nothing else in the suite would catch its loss."""
    gpu_claims["nvidia"]["dbgstat"] = "enabled"

    policy = _gpu_policy(tmp_path, ["580.173.02"])

    assert _appraise(opa, policy, gpu_claims, tmp_path)["configuration"] == 36


@pytest.mark.parametrize(
    "chain, denied",
    [
        ("x-nvidia-gpu-attestation-report-cert-chain", "hardware"),
        ("x-nvidia-gpu-driver-rim-cert-chain", "executables"),
        ("x-nvidia-gpu-vbios-rim-cert-chain", "executables"),
    ],
)
def test_gpu_policy_denies_a_revoked_certificate(
    opa,
    tmp_path,
    gpu_claims,
    chain,
    denied,
):
    """Every chain, not just the device's.

    A revoked RIM signing certificate passes x-nvidia-cert-status, so without
    the OCSP check a RIM NVIDIA has disowned would still license the
    measurements compared against it.
    """
    gpu_claims["nvidia"][chain]["x-nvidia-cert-ocsp-status"] = "revoked"

    policy = _gpu_policy(tmp_path, ["580.173.02"])

    assert _appraise(opa, policy, gpu_claims, tmp_path)[denied] == DENIED[denied]


def test_policies_matching_nothing_still_load_and_deny(
    opa,
    tmp_path,
    snp_claims,
    gpu_claims,
    capsys,
):
    """A requested type always emits a file, even covering no targets.

    Every generated helper has a default for exactly this: substituting a
    section to nothing leaves its name undefined, which Rego rejects as an
    unsafe variable rather than evaluating to false, so the policy would not
    load at all.
    """
    cpu = _cpu_policy(tmp_path, [], [])
    gpu = _gpu_policy(tmp_path, [])

    for policy in (cpu, gpu):
        check = subprocess.run(
            [opa, "check", str(policy)], capture_output=True, text=True
        )
        assert check.returncode == 0, check.stderr

    appraised = _appraise(opa, cpu, snp_claims, tmp_path)
    # hardware speaks only to the part and its TCB, which are still genuine;
    # the two dimensions the manifest populates are what must deny.
    assert appraised["executables"] == 33
    assert appraised["configuration"] == 36
    assert _appraise(opa, gpu, gpu_claims, tmp_path)["configuration"] == 36

    # An inert policy nobody notices is how a useless artifact ships.
    assert capsys.readouterr().out.count("::warning::") == 2
    assert cpu.read_text().startswith("# WARNING: this policy pins no")
    assert gpu.read_text().startswith("# WARNING: this policy pins no")


@pytest.mark.parametrize(
    "value",
    [
        "0" * 64 + '"\n}\ndefault configuration := 2\n#',
        "0" * 63,
        "0" * 64 + "0",
        "NOTHEXAT" * 8,
        None,
        1234,
    ],
)
def test_hostile_pcr_values_cannot_reach_the_policy(value):
    """Validated before substitution, so no manifest-derived value is Rego."""
    with pytest.raises(ValueError, match="Azure vTPM PCR"):
        trustee.validate_pcr_hex("pcr4", value)


@pytest.mark.parametrize(
    "value",
    [
        # Truncated, over-long, padded, and not base64 at all.
        "qnydpVwThuWxZTsSWXi+2ns/laha6w+d2723g84FaijJ0CHaI5w0pYw6ZXZUJw",
        "A" * 65,
        "A" * 62 + "==",
        "",
        None,
    ],
)
def test_launch_measurement_is_validated_as_base64_not_hex(value):
    """The value family the vTPM PCR validator must never be applied to.

    A launch measurement is base64 of 48 bytes, so 64 characters with no
    padding, while an Azure vTPM PCR is 64 hex characters. They are the same
    length, which is why each has its own validator.
    """
    assert trustee.validate_snp_launch_measurement(
        trustee.AZSNP_PARAVISOR_MEASUREMENTS[0]
    )
    with pytest.raises(ValueError, match="SNP launch measurement"):
        trustee.validate_snp_launch_measurement(value)


def test_rendered_lines_stay_well_under_the_regorus_column_cap(tmp_path):
    """regorus rejects a line over 1024 columns in the lexer, before parsing.

    The hazard is any collection whose length scales with the manifest, which
    passes at four entries and breaches silently at fifteen, so every set is
    emitted one element per line and this is what holds that.
    """
    pcrs = {name: "a" * 64 for name in ("pcr4", "pcr5", "pcr8", "pcr9", "pcr11")}
    policy = _cpu_policy(
        tmp_path,
        [(f"podvm-image-tag-number-{index}", pcrs) for index in range(40)],
        [(f"model-{index}", "b" * 64) for index in range(40)],
    )
    gpu = _gpu_policy(tmp_path, [f"580.159.{index:02d}" for index in range(40)])

    for path in (policy, gpu):
        longest = max(len(line) for line in path.read_text().splitlines())
        assert longest < 900, f"{path.name} has a {longest}-column line"


@pytest.mark.parametrize(
    "machine, appraisable",
    [
        ({"platform": "azure", "tee": "snp"}, True),
        ({"platform": "gcp", "tee": "tdx"}, False),
        ({"platform": "azure", "tee": "tdx"}, False),
    ],
)
def test_only_platforms_with_a_section_are_appraised(machine, appraisable):
    """Routing is by claim shape, so a pair is skipped until it has a section.

    (azure, tdx) is the cautionary one: it takes az-tdx-vtpm rather than tdx,
    because a vTPM platform emits PCRs alongside the TD quote, so the key
    cannot be inferred from the platform pair.
    """
    reason = trustee.TrusteeRenderer(output_dir=Path("/nonexistent")) \
        .cannot_appraise(machine)

    assert (reason is None) is appraisable


def test_renderer_measures_azure_targets_and_records_what_it_pinned(
    tmp_path,
    monkeypatch,
    snp_claims,
):
    """The renderer end to end, with the fetches and cvm-measure stubbed.

    Two targets on one image and one initdata each: the image block is shared
    and deduplicated, the initdata blocks are not, and the predicate carries
    the platform reference values that no target entry could state.
    """
    pcrs = _pcrs(snp_claims)
    monkeypatch.setattr(generate, "fetch_uki", lambda *args: None)
    monkeypatch.setattr(
        generate, "fetch_oci_digest", lambda ref: "sha256:123"
    )
    monkeypatch.setattr(
        trustee, "resolve_nvidia_driver_versions",
        lambda targets, artifacts: ["580.173.02"],
    )
    measured = []

    def fake_pcrs(*, initdata, uki_path, disk_path, output_dir):
        measured.append(hashlib.sha384(initdata).hexdigest())
        return {**pcrs, "pcr8": hashlib.sha256(initdata).hexdigest()}

    monkeypatch.setattr(trustee, "compute_azure_snp_pcrs", fake_pcrs)

    initdata_dir = tmp_path / "initdata"
    initdata_dir.mkdir()
    digests = []
    for body in (b"first", b"second"):
        digest = hashlib.sha384(body).hexdigest()
        (initdata_dir / f"{digest}.toml").write_bytes(body)
        digests.append(digest)

    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("targets:\n" + "".join(
        f"  - model: {model}\n"
        f"    machine_type: {machine_type}\n"
        "    podvm_image_tag: image-tag\n"
        f"    initdata_file: initdata/{digest}.toml\n"
        f"    initdata_sha384: {digest}\n"
        for model, machine_type, digest in [
            ("cat2508rws-l", "Standard_NCC40ads_H100_v5", digests[0]),
            ("cmp-l", "Standard_NCC40ads_H100_v5", digests[1]),
            ("cmp-l-tdx", "a3-highgpu-1g", digests[0]),
        ]
    ))
    predicate = tmp_path / "predicate.json"
    renderer = trustee.TrusteeRenderer(output_dir=tmp_path / "policies")

    generate.generate_policy(
        manifest_file=manifest,
        podvm_image="ghcr.io/owner/podvm",
        artifacts_dir=tmp_path / "artifacts",
        renderers=[renderer],
        predicate_file=predicate,
    )

    # The TDX target has no section, so it is never measured.
    assert measured == [digests[0], digests[1]]
    policy = renderer.cpu_policy_file.read_text()
    assert policy.count("azsnp_image_ok if {") == 1
    assert policy.count("azsnp_initdata_ok if {") == 2
    assert "# PodVM image: image-tag" in policy

    written = json.loads(predicate.read_text())
    assert written["target_counts"] == {"trustee": 2}
    assert [entry["model"] for entry in written["targets"]] == [
        "cat2508rws-l", "cmp-l",
    ]
    assert written["targets"][0]["azure_snp"]["pcr4"] == pcrs["pcr4"]
    # The machine table entry reaches the predicate, so the signed artifact
    # keeps stating the attributes that produced each measurement.
    assert written["targets"][0]["platform"] == "azure"

    policies = written["trustee_policies"]
    assert policies["policy_id"] == trustee.POLICY_ID
    assert policies["files"] == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in renderer.policy_files
    }
    # The reference values the predicate records are the ones the policy
    # enforces, rather than a second copy that can drift from them.
    for measurement in policies["azure_snp"]["paravisor_measurements"]:
        assert measurement in policy
    for component, floor in policies["azure_snp"]["min_tcb"].items():
        assert f'"{component}": {floor},' in policy
