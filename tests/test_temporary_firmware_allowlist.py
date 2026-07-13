"""Unit tests for temporary GCP TDX firmware allowlist expansion."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ACTION_ROOT = REPO_ROOT / ".github" / "actions" / "generate-policy"
sys.path.insert(0, str(ACTION_ROOT))

from generate_policy import generate as gen  # noqa: E402


def test_expand_preserves_model_rtmrs_and_swaps_mrtd_rtmr0():
    measurements = {
        "mrtd": "a" * 96,
        "rtmr0": "b" * 96,
        "rtmr1": "c" * 96,
        "rtmr2": "d" * 96,
        "rtmr3": "e" * 96,
    }
    allowlist = [
        {
            "name": "gcp-a3-new-firmware",
            "mrtd": "9bf86e6280ec4282b8b5822d8166410a456cdb720109aa799f0011fa63df1de3ee5e35e293fc410c061433163acb03a6",
            "rtmr0": "cacdba001f7732b60c1a60cac95e361717574cc4e1b13056cec49059d3229b3ea41381d00566b320318577ef74f91c4e",
        }
    ]

    variants = gen.expand_measurements_for_temporary_gcp_firmware_allowlist(
        measurements, allowlist
    )
    assert len(variants) == 2
    assert variants[0] == (None, measurements)

    label, variant = variants[1]
    assert label == "gcp-a3-new-firmware"
    assert variant["mrtd"] == allowlist[0]["mrtd"]
    assert variant["rtmr0"] == allowlist[0]["rtmr0"]
    assert variant["rtmr1"] == measurements["rtmr1"]
    assert variant["rtmr2"] == measurements["rtmr2"]
    assert variant["rtmr3"] == measurements["rtmr3"]


def test_expand_skips_duplicate_mrtd_rtmr0():
    measurements = {
        "mrtd": "9bf86e6280ec4282b8b5822d8166410a456cdb720109aa799f0011fa63df1de3ee5e35e293fc410c061433163acb03a6",
        "rtmr0": "cacdba001f7732b60c1a60cac95e361717574cc4e1b13056cec49059d3229b3ea41381d00566b320318577ef74f91c4e",
        "rtmr1": "c" * 96,
    }
    allowlist = [
        {
            "name": "same-as-measured",
            "mrtd": measurements["mrtd"],
            "rtmr0": measurements["rtmr0"],
        }
    ]
    variants = gen.expand_measurements_for_temporary_gcp_firmware_allowlist(
        measurements, allowlist
    )
    assert variants == [(None, measurements)]


def test_load_allowlist_validates_hex_length(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text('[{"name": "x", "mrtd": "abc", "rtmr0": "' + ("0" * 96) + '"}]')
    with pytest.raises(SystemExit):
        gen.load_temporary_gcp_tdx_firmware_allowlist(bad)


def test_render_policy_emits_allowlist_comment(tmp_path: Path):
    template = tmp_path / "template.rego"
    template.write_text("${TDX_MATCH_BLOCKS}\n${POLICY_NONCE}\n${NVIDIA_DRIVER_VERSION}\n")
    output = tmp_path / "out.rego"

    targets = [
        {
            "model": "cmp-l",
            "measurements": {
                "mrtd": "a" * 96,
                "rtmr0": "b" * 96,
                "rtmr1": "c" * 96,
                "rtmr2": "d" * 96,
                "rtmr3": "e" * 96,
            },
        }
    ]
    allowlist = [
        {
            "name": "gcp-a3-new-firmware",
            "mrtd": "9bf86e6280ec4282b8b5822d8166410a456cdb720109aa799f0011fa63df1de3ee5e35e293fc410c061433163acb03a6",
            "rtmr0": "cacdba001f7732b60c1a60cac95e361717574cc4e1b13056cec49059d3229b3ea41381d00566b320318577ef74f91c4e",
        }
    ]

    gen.render_policy(
        targets,
        "580.159.04",
        template,
        output,
        temporary_firmware_allowlist=allowlist,
    )
    policy = output.read_text()
    assert policy.count("matches_tdx if {") == 2
    assert (
        "# Target 0: cmp-l (TEMPORARY GCP firmware allowlist: "
        "gcp-a3-new-firmware)" in policy
    )
    assert policy.count("c" * 96) == 2
