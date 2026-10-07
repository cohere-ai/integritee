"""Tests for the staging policy release lane.

The staging lane exists so unmerged Blobheart changes can be attested on dev.
Its one hard requirement is that nothing it publishes can be mistaken for, or
interfere with, a production release. These tests pin each axis of that
isolation: tag, signer identity, ITA target and release flags.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
STAGING_MANAGE = ".github/workflows/release-policy-staging/manage.py"
SHA = "a" * 40


def load_module(name: str, relative_path: str):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def manage():
    return load_module("staging_manage", STAGING_MANAGE)


@pytest.fixture
def github_output(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(path))
    return path


def read_outputs(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def workflow(name: str) -> dict:
    return yaml.safe_load((REPO_ROOT / f".github/workflows/{name}.yaml").read_text())


def staging_text() -> str:
    return (REPO_ROOT / ".github/workflows/release-policy-staging.yaml").read_text()


# ---------------------------------------------------------------------------
# Tag
# ---------------------------------------------------------------------------


def test_staging_version_never_matches_production_numbering(manage):
    production = load_module(
        "release_manage", ".github/workflows/release-policy/manage.py"
    )
    version = manage.staging_version("37535936465", "2")

    assert version == "staging-37535936465-2"
    # Production next_version() only counts v0.0.1aN tags, and the
    # release-tags ruleset only governs v*, so a staging tag can neither
    # advance production numbering nor be blocked by its tag rules.
    assert not production.ALPHA_TAG_RE.fullmatch(version)
    assert not version.startswith("v")


@pytest.mark.parametrize("run_id", ["", "abc", "1;rm -rf /"])
def test_staging_version_rejects_non_numeric_run(manage, run_id):
    with pytest.raises(SystemExit, match="invalid staging version"):
        manage.staging_version(run_id, "1")


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


def inputs(**overrides) -> argparse.Namespace:
    values = {
        "blobheart_refs": "",
        "manifest_run_id": "",
        "manifest_artifact": "staging-policy-manifest",
        "run_id": "123",
        "run_attempt": "1",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_resolve_inputs_accepts_unmerged_blobheart_refs(manage, github_output):
    manage.resolve_inputs(inputs(blobheart_refs=f"{SHA} {'b' * 40}"))

    assert read_outputs(github_output) == {
        "version": "staging-123-1",
        "source": "refs",
    }


def test_resolve_inputs_accepts_a_blobheart_run(manage, github_output):
    manage.resolve_inputs(inputs(manifest_run_id="987654321"))

    assert read_outputs(github_output)["source"] == "run"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({}, "exactly one"),
        ({"blobheart_refs": SHA, "manifest_run_id": "1"}, "exactly one"),
        ({"blobheart_refs": "main"}, "invalid Blobheart commit SHA"),
        ({"blobheart_refs": SHA.upper()}, "invalid Blobheart commit SHA"),
        ({"manifest_run_id": "12a"}, "invalid Blobheart run ID"),
        (
            {"manifest_run_id": "1", "manifest_artifact": "../escape"},
            "invalid artifact name",
        ),
    ],
)
def test_resolve_inputs_rejects_bad_sources(
    manage, github_output, overrides, message
):
    with pytest.raises(SystemExit, match=message):
        manage.resolve_inputs(inputs(**overrides))


def test_resolve_inputs_does_not_require_blobheart_main(manage, github_output):
    manage.run = Mock(side_effect=AssertionError("must not call GitHub"))

    manage.resolve_inputs(inputs(blobheart_refs=SHA))


# ---------------------------------------------------------------------------
# Blobheart run artifact
# ---------------------------------------------------------------------------


def write_artifact(root: Path, files: dict[str, bytes] | None = None) -> Path:
    initdata = root / "initdata"
    initdata.mkdir(parents=True)
    body = b"[data]\npolicy = 'x'\n"
    digest = hashlib.sha384(body).hexdigest()
    for name, content in (
        {f"{digest}.toml": body} if files is None else files
    ).items():
        (initdata / name).write_bytes(content)
    (root / "policy-manifest.yaml").write_text("schema_version: 1\ntargets: []\n")
    return root


def test_artifact_manifest_is_accepted_and_reported(
    manage, tmp_path, github_output
):
    artifact = write_artifact(tmp_path / "artifact")

    manage.check_artifact_manifest(argparse.Namespace(artifact_dir=artifact))

    outputs = read_outputs(github_output)
    assert outputs["manifest_file"] == str(artifact / "policy-manifest.yaml")
    assert outputs["initdata_dir"] == str(artifact / "initdata")


def test_artifact_initdata_must_match_its_content_address(
    manage, tmp_path, github_output
):
    artifact = write_artifact(
        tmp_path / "artifact", {f"{'0' * 96}.toml": b"tampered"}
    )

    with pytest.raises(SystemExit, match="digest does not match"):
        manage.check_artifact_manifest(argparse.Namespace(artifact_dir=artifact))


def test_artifact_rejects_extra_entries(manage, tmp_path, github_output):
    artifact = write_artifact(tmp_path / "artifact")
    (artifact / "ita_policy.rego").write_text("package policy\n")

    with pytest.raises(SystemExit, match="unexpected artifact entries"):
        manage.check_artifact_manifest(argparse.Namespace(artifact_dir=artifact))


def test_artifact_rejects_symlinked_initdata(manage, tmp_path, github_output):
    artifact = write_artifact(tmp_path / "artifact")
    target = next((artifact / "initdata").iterdir())
    link = artifact / "initdata" / f"{'1' * 96}.toml"
    link.symlink_to(target)

    with pytest.raises(SystemExit, match="unexpected initdata file"):
        manage.check_artifact_manifest(argparse.Namespace(artifact_dir=artifact))


def test_artifact_rejects_empty_initdata(manage, tmp_path, github_output):
    artifact = write_artifact(tmp_path / "artifact", {})

    with pytest.raises(SystemExit, match="initdata directory is empty"):
        manage.check_artifact_manifest(argparse.Namespace(artifact_dir=artifact))


# ---------------------------------------------------------------------------
# ITA target
# ---------------------------------------------------------------------------


def ita(**overrides) -> argparse.Namespace:
    values = {
        "api_key": "key",
        "api_url": "https://api.trustauthority.intel.com",
        "policy_id": "11111111-2222-3333-4444-555555555555",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_ita_target_refuses_the_production_policy(manage):
    with pytest.raises(SystemExit, match="production ITA policy"):
        manage.check_ita_target(ita(policy_id=manage.PRODUCTION_ITA_POLICY_ID))


def test_production_policy_id_matches_the_production_workflow(manage):
    release = workflow("release-policy")

    assert release["jobs"]["publish"]["env"]["ITA_POLICY_ID"] == (
        manage.PRODUCTION_ITA_POLICY_ID
    )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"api_key": ""}, "STAGING_ITA_ADMIN_API_KEY"),
        ({"api_url": ""}, "STAGING_ITA_API_URL"),
        ({"policy_id": "not-a-uuid"}, "invalid STAGING_ITA_POLICY_ID"),
    ],
)
def test_ita_target_requires_staging_credentials(manage, overrides, message):
    with pytest.raises(SystemExit, match=message):
        manage.check_ita_target(ita(**overrides))


def test_ita_target_allows_creating_the_staging_policy(manage, capsys):
    manage.check_ita_target(ita(policy_id=""))

    assert "creates the staging policy" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Predicate and release notes
# ---------------------------------------------------------------------------


def test_predicate_records_channel_and_source(manage, tmp_path):
    predicate = tmp_path / "predicate.json"
    predicate.write_text(json.dumps({"version": "staging-1-1"}))

    manage.annotate_predicate(
        argparse.Namespace(
            predicate=predicate,
            blobheart_refs="",
            manifest_run_id="42",
            manifest_artifact="staging-policy-manifest",
        )
    )

    result = json.loads(predicate.read_text())
    assert result["version"] == "staging-1-1"
    assert result["channel"] == "staging"
    assert result["blobheart_manifest_run"] == {
        "repository": "cohere-ai/blobheart",
        "run_id": 42,
        "artifact": "staging-policy-manifest",
    }


def test_release_notes_give_the_tng_policy_source(manage, tmp_path):
    notes = tmp_path / "release-body.md"
    notes.write_text("**ITA Policy ID:** `x`\n")

    manage.release_notes(
        argparse.Namespace(
            notes=notes,
            version="staging-9-1",
            repository="cohere-ai/integritee",
        )
    )

    text = notes.read_text()
    assert text.startswith("**Staging release.**")
    assert text.endswith("**ITA Policy ID:** `x`\n")
    config = json.loads(text.split("```json\n", 1)[1].split("\n```", 1)[0])
    assert config == {
        "url": (
            "https://github.com/cohere-ai/integritee/releases/download/staging-9-1"
        ),
        "version": "staging-9-1",
        "provenance": {
            "repo": "cohere-ai/integritee",
            "signer_workflow": ".github/workflows/release-policy-staging.yaml",
            "source_ref": "refs/heads/main",
            "predicate_type": "https://cohere.com/attestation-policy/staging/v1",
            "environment": "staging",
        },
    }


# ---------------------------------------------------------------------------
# Pruning
# ---------------------------------------------------------------------------


def test_prune_only_deletes_old_staging_prereleases(manage, monkeypatch):
    releases = [
        {"tagName": "v0.0.1a73", "isPrerelease": False, "createdAt": "2026-10-06"},
        {"tagName": "v0.0.1a74", "isPrerelease": True, "createdAt": "2026-10-09"},
        {"tagName": "staging-3-1", "isPrerelease": True, "createdAt": "2026-10-08"},
        {"tagName": "staging-2-1", "isPrerelease": True, "createdAt": "2026-10-07"},
        {"tagName": "staging-1-1", "isPrerelease": True, "createdAt": "2026-10-05"},
        {"tagName": "staging-0-1", "isPrerelease": False, "createdAt": "2026-10-01"},
    ]
    calls = []

    def fake_run(*command, capture_output=False):
        calls.append(command)
        return json.dumps(releases) if command[:3] == ("gh", "release", "list") else ""

    monkeypatch.setattr(manage, "run", fake_run)

    manage.prune(argparse.Namespace(keep=1))

    deleted = [command[3] for command in calls if command[:3] == ("gh", "release", "delete")]
    assert deleted == ["staging-2-1", "staging-1-1"]


def test_prune_keeps_at_least_one(manage):
    with pytest.raises(SystemExit, match="at least 1"):
        manage.prune(argparse.Namespace(keep=0))


# ---------------------------------------------------------------------------
# Workflow wiring
# ---------------------------------------------------------------------------


def test_staging_publish_is_isolated_from_production():
    staging = workflow("release-policy-staging")
    production = workflow("release-policy")
    publish = staging["jobs"]["publish"]
    text = staging_text()

    # Its own environment, never production's.
    assert publish["environment"] == "staging"
    assert production["jobs"]["publish"]["environment"] == "release"

    # Main only, so the signer identity is one fixed string to pin.
    assert "refs/heads/main" in publish["if"]

    # Its own predicate type, so production verifiers reject the bundle.
    attest = next(s for s in publish["steps"] if s.get("id") == "attest")
    assert attest["with"]["predicate-type"] == (
        "https://cohere.com/attestation-policy/staging/v1"
    )
    prod_attest = next(
        s for s in production["jobs"]["publish"]["steps"] if s.get("id") == "attest"
    )
    assert prod_attest["with"]["predicate-type"] != attest["with"]["predicate-type"]

    # Staging-named ITA credentials only: the repository-level production key
    # must never be reachable from this workflow.
    assert "secrets.ITA_ADMIN_API_KEY" not in text
    assert "secrets.ITA_API_URL" not in text
    assert "cbeedffa-e224-4664-b6b4-573fcd4133d3" not in text
    assert "integritee-policy-a" not in text

    # A prerelease that never becomes latest.
    create = next(s for s in publish["steps"] if s.get("name") == "Create staging release")
    assert "--prerelease" in create["run"]
    assert "--latest=false" in create["run"]

    # The staging guard runs before any ITA call.
    names = [step.get("name") for step in publish["steps"]]
    assert names.index("Check staging ITA target") < names.index(
        "Upload policy to staging ITA"
    )


def test_staging_generate_has_no_publish_credentials():
    generate = workflow("release-policy-staging")["jobs"]["generate"]
    text = str(generate)

    assert "environment" not in generate
    assert "ITA_ADMIN_API_KEY" not in text
    assert "CC_POLICY_APP" not in text
    assert "attestations" not in generate["permissions"]


def test_staging_never_commits_the_merged_manifest():
    text = staging_text()

    assert "manage.py publish" not in text
    assert "git push" not in text
    assert "permission-contents: write" in text  # only for the release token
    publish_steps = workflow("release-policy-staging")["jobs"]["publish"]["steps"]
    writers = [
        step["name"]
        for step in publish_steps
        if "release-token.outputs.token" in str(step)
    ]
    assert writers == ["Create staging release", "Prune old staging releases"]


def test_staging_and_production_do_not_share_a_concurrency_group():
    staging = workflow("release-policy-staging")["concurrency"]["group"]
    production = workflow("release-policy")["concurrency"]["group"]

    assert staging != production
