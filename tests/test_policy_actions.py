from __future__ import annotations

import argparse
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
TEST_SHA = "a" * 40


def load_action(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(
        name,
        REPO_ROOT / relative_path,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def install_http_import_stubs(monkeypatch) -> None:
    requests = types.ModuleType("requests")
    requests.Session = Mock
    adapters = types.ModuleType("requests.adapters")
    adapters.HTTPAdapter = Mock
    retry = types.ModuleType("urllib3.util.retry")
    retry.Retry = Mock
    monkeypatch.setitem(sys.modules, "requests", requests)
    monkeypatch.setitem(sys.modules, "requests.adapters", adapters)
    monkeypatch.setitem(sys.modules, "urllib3.util.retry", retry)


def test_derive_fails_when_all_discovered_models_are_skipped(
    tmp_path,
    monkeypatch,
    capsys,
):
    derive = load_action(
        "derive_manifest",
        ".github/actions/derive-manifest/derive.py",
    )
    output = tmp_path / "manifest.yaml"
    monkeypatch.setattr(derive, "resolve_local_ref", lambda _root: TEST_SHA)
    monkeypatch.setattr(derive, "list_dir", lambda *_args: ["cmp-l-cc"])
    monkeypatch.setattr(
        derive,
        "read_file",
        lambda _root, _ref, path: (
            "resources: []\n"
            if path == derive.KUSTOMIZATION_PATH
            else "kind: StatefulSet\nmetadata:\n  labels: {}\n"
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "derive.py",
            "--blobheart-dir",
            str(tmp_path),
            "--output",
            str(output),
        ],
    )

    with pytest.raises(SystemExit, match="1"):
        derive.main()

    assert "none produced a policy target" in capsys.readouterr().err
    assert not output.exists()


def test_derive_preserves_empty_manifest_for_source_without_cc_models(
    tmp_path,
    monkeypatch,
):
    derive = load_action(
        "derive_manifest_empty",
        ".github/actions/derive-manifest/derive.py",
    )
    output = tmp_path / "manifest.yaml"
    monkeypatch.setattr(derive, "resolve_local_ref", lambda _root: TEST_SHA)
    monkeypatch.setattr(derive, "list_dir", lambda *_args: [])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "derive.py",
            "--blobheart-dir",
            str(tmp_path),
            "--output",
            str(output),
        ],
    )

    derive.main()

    assert yaml.safe_load(output.read_text()) == {"targets": []}


def test_derive_propagates_source_read_failures(tmp_path, monkeypatch):
    derive = load_action(
        "derive_manifest_read_failure",
        ".github/actions/derive-manifest/derive.py",
    )
    output = tmp_path / "manifest.yaml"
    monkeypatch.setattr(derive, "resolve_local_ref", lambda _root: TEST_SHA)
    monkeypatch.setattr(derive, "list_dir", lambda *_args: ["cmp-l-cc"])

    def read_file(_root, _ref, path):
        if path == derive.KUSTOMIZATION_PATH:
            return "resources: []\n"
        raise RuntimeError("source API unavailable")

    monkeypatch.setattr(derive, "read_file", read_file)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "derive.py",
            "--blobheart-dir",
            str(tmp_path),
            "--output",
            str(output),
        ],
    )

    with pytest.raises(RuntimeError, match="source API unavailable"):
        derive.main()

    assert not output.exists()


def test_prune_refuses_to_write_empty_manifest(tmp_path, monkeypatch):
    prune = load_action(
        "prune_manifest",
        ".github/workflows/prune-from-blobheart/prune.py",
    )
    manifest = tmp_path / "policy-manifest.yaml"
    original = (
        "targets:\n"
        "  - model: cmp-l\n"
        "    sources:\n"
        "      - abc123\n"
    )
    manifest.write_text(original)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prune.py",
            "--manifest",
            str(manifest),
            "--retire",
            "abc123",
        ],
    )

    with pytest.raises(SystemExit, match="at least one target must remain"):
        prune.main()

    assert manifest.read_text() == original


def test_prune_deletes_initdata_orphaned_by_removed_targets(tmp_path, monkeypatch):
    prune = load_action(
        "prune_initdata",
        ".github/workflows/prune-from-blobheart/prune.py",
    )
    orphan, kept = "c" * 96, "d" * 96
    targets = [
        {"initdata_file": f"initdata/{digest}.toml", "initdata_sha384": digest,
         "sources": sources}
        for digest, sources in ((orphan, [TEST_SHA]), (kept, [TEST_SHA, "b" * 40]))
    ]
    initdata = tmp_path / "initdata"
    initdata.mkdir()
    for target in targets:
        (initdata / Path(target["initdata_file"]).name).touch()
    manifest = tmp_path / "policy-manifest.yaml"
    manifest.write_text(yaml.dump({"targets": targets}))
    monkeypatch.setattr(
        sys,
        "argv",
        ["prune.py", "--manifest", str(manifest), "--retire", TEST_SHA],
    )

    prune.main()

    survivors = yaml.safe_load(manifest.read_text())["targets"]
    assert [target["initdata_sha384"] for target in survivors] == [kept]
    assert [path.name for path in initdata.iterdir()] == [f"{kept}.toml"]


@pytest.mark.parametrize("status", ["ahead", "identical"])
def test_blobheart_ref_validation_accepts_main_ancestors(status, monkeypatch):
    manage = load_action(
        f"add_from_blobheart_{status}",
        ".github/workflows/add-from-blobheart/manage.py",
    )
    run = Mock(return_value=Mock(stdout=f"{status}\n"))
    monkeypatch.setattr(manage, "run", run)
    ref = "a" * 40

    manage.validate(
        argparse.Namespace(blobheart_refs=ref, dry_run="false")
    )

    assert f"{ref}...main" in run.call_args.args[2]
    assert run.call_args.kwargs["timeout"] == 30


def test_blobheart_ref_validation_rejects_feature_commit(monkeypatch):
    manage = load_action(
        "add_from_blobheart_diverged",
        ".github/workflows/add-from-blobheart/manage.py",
    )
    monkeypatch.setattr(
        manage,
        "run",
        Mock(return_value=Mock(stdout="diverged\n")),
    )

    with pytest.raises(SystemExit, match="is not an ancestor of main"):
        manage.validate(
            argparse.Namespace(
                blobheart_refs="a" * 40,
                dry_run="false",
            )
        )


def test_local_derivation_uses_checkout_commit(monkeypatch, tmp_path):
    derive = load_action(
        "derive_manifest_local_ref",
        ".github/actions/derive-manifest/derive.py",
    )
    run = Mock(returncode=0, stdout=f"{TEST_SHA}\n", stderr="")
    monkeypatch.setattr(derive.subprocess, "run", Mock(return_value=run))

    assert derive.resolve_local_ref(tmp_path) == TEST_SHA


def test_release_manifest_downloads_into_directory(tmp_path, monkeypatch):
    verify = load_action(
        "verify_against_policy",
        ".github/actions/verify-against-policy/verify.py",
    )
    calls = []

    def fake_gh(*args, token=None):
        calls.append(args)
        if args[:2] == ("release", "view"):
            return "v1.2.3"
        download_dir = Path(args[args.index("--dir") + 1])
        (download_dir / "policy-manifest.yaml").write_text("targets: []\n")
        return ""

    monkeypatch.setattr(verify, "gh", fake_gh)

    manifest, tag = verify.fetch_release_manifest(tmp_path, "token")

    assert tag == "v1.2.3"
    assert manifest == tmp_path / "integritee-release" / "policy-manifest.yaml"
    download_call = calls[1]
    assert "--dir" in download_call
    assert "--clobber" in download_call
    assert "--output" not in download_call


def test_policy_coverage_failure_explains_release_race():
    verify = load_action(
        "verify_policy_failure_message",
        ".github/actions/verify-against-policy/verify.py",
    )

    message = verify.coverage_failure_message(
        "v1.2.3",
        2,
        "cmp-l-cc,e4-l-cc",
        local_manifest=False,
    )

    assert "Latest Integritee policy release is not ready" in message
    assert "2 target(s) are not covered by v1.2.3: cmp-l-cc,e4-l-cc" in message
    assert "policy release may still be running" in message
    assert verify.RELEASE_WORKFLOW_URL in message
    assert "rerun the deployment" in message


def test_local_policy_coverage_failure_does_not_suggest_waiting():
    verify = load_action(
        "verify_local_policy_failure_message",
        ".github/actions/verify-against-policy/verify.py",
    )

    message = verify.coverage_failure_message(
        "local",
        1,
        "cmp-l-cc",
        local_manifest=True,
    )

    assert message == (
        "ERROR: Local policy verification failed. "
        "1 target(s) are not covered by local: cmp-l-cc"
    )
    assert verify.RELEASE_WORKFLOW_URL not in message


def _load_workflow(name: str) -> dict:
    return yaml.safe_load(
        (REPO_ROOT / f".github/workflows/{name}.yaml").read_text()
    )


def test_workflows_use_explicit_publish_gates():
    """Each workflow splits generate from publish, with write credentials
    only in the publish job, behind the release environment."""

    release = _load_workflow("release-policy")
    add = _load_workflow("add-from-blobheart")
    prune = _load_workflow("prune-from-blobheart")

    # release-policy: publish only on main, gated by the release environment.
    release_publish = release["jobs"]["publish"]
    assert release_publish["environment"] == "release"
    assert "refs/heads/main" in release_publish["if"]
    assert (
        "push" in release_publish["if"]
        or "inputs.publish" in release_publish["if"]
    )
    release_generate = release["jobs"]["generate"]
    assert "ITA_ADMIN_API_KEY" not in str(release_generate)
    assert "CC_POLICY_APP" not in str(release_generate)

    # add-from-blobheart: generate has no write credentials, publish has
    # the release environment and the CC_POLICY_APP token. Publish always
    # pushes to main (no PR path) and only runs on main.
    add_generate = add["jobs"]["generate"]
    assert "CC_POLICY_APP" not in str(add_generate)
    add_publish = add["jobs"]["publish"]
    assert add_publish["environment"] == "release"
    assert "refs/heads/main" in add_publish["if"]
    assert "CC_POLICY_APP" in str(add_publish)

    # prune-from-blobheart: same pattern.
    prune_job = prune["jobs"]["prune"]
    assert "CC_POLICY_APP" not in str(prune_job)
    prune_publish = prune["jobs"]["publish"]
    assert prune_publish["environment"] == "release"
    assert "CC_POLICY_APP" in str(prune_publish)


def test_resolved_release_version_is_a_step_output(tmp_path, monkeypatch):
    manage = load_action(
        "release_manage",
        ".github/workflows/release-policy/manage.py",
    )
    github_output = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

    manage.resolve_version(argparse.Namespace(requested="v1.2.3"))

    assert github_output.read_text() == "version=v1.2.3\n"
    workflow = (
        REPO_ROOT / ".github/workflows/release-policy.yaml"
    ).read_text()
    assert "id: version" in workflow
    assert workflow.count("${{ steps.version.outputs.version }}") == 2
    assert not any(
        line.strip().startswith("VERSION: ${{ inputs.version")
        for line in workflow.splitlines()
    )


@pytest.mark.parametrize(
    ("tags", "sha_tags", "expected"),
    [
        ([], [], ("actions-v1.0.0", True)),
        (
            ["actions-v1.0.9", "actions-v1.0.10", "v0.0.1a1"],
            [],
            ("actions-v1.0.11", True),
        ),
        (
            ["actions-v1.0.9", "actions-v2.3.4"],
            ["actions-v2.3.4"],
            ("actions-v2.3.4", False),
        ),
    ],
)
def test_resolve_action_release_version(tags, sha_tags, expected):
    manage = load_action(
        "release_actions_manage",
        ".github/workflows/release-actions/manage.py",
    )

    assert manage.resolve_version(tags, sha_tags) == expected


@pytest.mark.parametrize(
    ("relative_path", "request_method"),
    [
        (".github/actions/fetch-ita-policy/fetch.py", "get"),
        (".github/actions/delete-ita-policy/delete.py", "delete"),
    ],
)
def test_ita_read_and_delete_requests_have_timeouts(
    relative_path,
    request_method,
    tmp_path,
    monkeypatch,
):
    install_http_import_stubs(monkeypatch)
    action = load_action(f"ita_{request_method}", relative_path)
    response = Mock(ok=True, status_code=200)
    response.json.return_value = {
        "policy": "package policy",
        "policy_name": "test-policy",
    }
    session = Mock()
    getattr(session, request_method).return_value = response
    monkeypatch.setattr(action, "ita_session", lambda: session)
    monkeypatch.setenv("POLICY_ID", "test-policy-id")
    monkeypatch.setenv("ITA_API_KEY", "test-api-key")
    monkeypatch.setenv("ITA_API_URL", "https://example.com")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))

    action.main()

    request = getattr(session, request_method)
    assert request.call_args.kwargs["timeout"] == 30


@pytest.mark.parametrize(
    ("policy_id", "request_method"),
    [
        ("", "post"),
        ("test-policy-id", "put"),
    ],
)
def test_ita_upload_requests_have_timeouts(
    policy_id,
    request_method,
    tmp_path,
    monkeypatch,
):
    install_http_import_stubs(monkeypatch)
    upload = load_action(
        f"ita_upload_{request_method}",
        ".github/actions/upload-ita-policy/upload.py",
    )
    policy = tmp_path / "policy.rego"
    policy.write_text("package policy\n")
    response = Mock(ok=True, status_code=200)
    response.json.return_value = {"policy_id": "test-policy-id"}
    session = Mock()
    getattr(session, request_method).return_value = response
    monkeypatch.setattr(upload, "ita_session", lambda: session)
    monkeypatch.setenv("POLICY_FILE", str(policy))
    monkeypatch.setenv("POLICY_NAME", "test-policy")
    monkeypatch.setenv("POLICY_ID", policy_id)
    monkeypatch.setenv("ITA_API_KEY", "test-api-key")
    monkeypatch.setenv("ITA_API_URL", "https://example.com")

    upload.main()

    request = getattr(session, request_method)
    assert request.call_args.kwargs["timeout"] == 30
