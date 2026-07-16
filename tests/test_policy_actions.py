from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent


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
