from __future__ import annotations

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


def test_workflows_use_explicit_dry_run_gates():
    add_workflow = (
        REPO_ROOT / ".github/workflows/add-from-blobheart.yaml"
    ).read_text()
    prune_workflow = (
        REPO_ROOT / ".github/workflows/prune-from-blobheart.yaml"
    ).read_text()
    release_workflow = (
        REPO_ROOT / ".github/workflows/release-policy.yaml"
    ).read_text()

    assert "&& 'true' || 'false'" in add_workflow
    assert "inputs.dry_run && 'true' || 'false'" in prune_workflow
    assert "DRY_RUN:" not in release_workflow
    assert release_workflow.count(
        "if: github.event_name == 'push' || inputs.dry_run == false"
    ) == 7


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
