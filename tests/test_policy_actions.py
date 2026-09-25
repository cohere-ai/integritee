from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
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


def rendered_cc_model(
    name: str,
    *,
    provider: str | None = "gcp",
    runtime_class: str | None = "kata-remote",
    machine_type: str | None = "a3-highgpu-1g",
    image: str | None = "projects/cohere-artifacts/global/images/podvm-gcp",
    initdata: str | None = "",
    confidential: bool = True,
    workload_count: int = 1,
    attestation_mode: str | None = None,
) -> str:
    if initdata == "":
        initdata = base64.b64encode(f"policy = '{name}'\n".encode()).decode()
    documents: list[dict] = [{"apiVersion": "v1", "kind": "ConfigMap"}]
    for index in range(workload_count):
        labels = {
            "cohere.com/confidential-compute": "true" if confidential else "false",
            "cohere.com/gpu": "h100-80g",
        }
        if provider is not None:
            labels["cohere.com/provider"] = provider
        annotations = {}
        if machine_type is not None:
            annotations[
                "io.katacontainers.config.hypervisor.machine_type"
            ] = machine_type
        if image is not None:
            annotations["io.katacontainers.config.hypervisor.image"] = image
        if initdata is not None:
            annotations[
                "io.katacontainers.config.hypervisor.cc_init_data"
            ] = initdata
        if attestation_mode is not None:
            annotations["cohere.com/cc-attestation-mode"] = attestation_mode
        template_spec = {}
        if runtime_class is not None:
            template_spec["runtimeClassName"] = runtime_class
        documents.append(
            {
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "metadata": {
                    "name": f"{name}-{index}",
                    "labels": labels,
                },
                "spec": {
                    "template": {
                        "metadata": {"annotations": annotations},
                        "spec": template_spec,
                    }
                },
            }
        )
    return yaml.safe_dump_all(documents, sort_keys=False)


def run_local_derive(
    derive,
    root: Path,
    output: Path,
    monkeypatch,
    *,
    listed: list[str] | None = None,
    list_output: str | None = None,
    builds: dict[str, str] | None = None,
    existing_models: list[str] | None = None,
    generated_dir: str | None = None,
    extra_args: list[str] | None = None,
    calls: list | None = None,
) -> list:
    listed = listed or []
    builds = builds or {}
    generated_dir = generated_dir or derive.DEFAULT_GENERATED_DIR
    existing_models = existing_models if existing_models is not None else list(builds)
    calls = calls if calls is not None else []
    (root / derive.BLOBHEART_MODELS_DIR).mkdir(parents=True, exist_ok=True)
    for model_id in existing_models:
        (root / generated_dir / model_id).mkdir(parents=True, exist_ok=True)

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[0].endswith("list-models.sh"):
            stdout = (
                list_output
                if list_output is not None
                else "".join(f"{model_id}\n" for model_id in listed)
            )
        elif command[:2] == ["kustomize", "build"]:
            stdout = builds[Path(command[2]).name]
        else:
            raise AssertionError(f"unexpected command: {command}")
        return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(derive, "resolve_local_ref", lambda _root: TEST_SHA)
    monkeypatch.setattr(derive.subprocess, "run", fake_run)
    argv = [
        "derive.py",
        "--blobheart-dir",
        str(root),
        "--generated-dir",
        generated_dir,
        "--output",
        str(output),
    ]
    argv.extend(extra_args or [])
    monkeypatch.setattr(sys, "argv", argv)
    derive.main()
    return calls


def test_derive_provider_specific_targets_and_plain_build_commands(
    tmp_path,
    monkeypatch,
):
    derive = load_action(
        "derive_manifest_provider_targets",
        ".github/actions/derive-manifest/derive.py",
    )
    output = tmp_path / "manifest.yaml"
    builds = {
        "cmp-l-cc": rendered_cc_model("cmp-l-cc"),
        "cmp-l-azure-cc": rendered_cc_model(
            "cmp-l-azure-cc",
            provider="azure",
            runtime_class="kata-remote-azure",
            machine_type="Standard_NCC40ads_H100_v5",
            image=(
                "/subscriptions/00000000-0000-0000-0000-000000000000"
                "/resourceGroups/RG-PODVM-IMAGES/providers/Microsoft.Compute"
                "/galleries/cohere_podvm_gallery/images/podvm-azure"
                "/versions/2026.924.1790266523"
            ),
        ),
    }

    calls = run_local_derive(
        derive,
        tmp_path,
        output,
        monkeypatch,
        listed=list(builds),
        builds=builds,
    )

    targets = yaml.safe_load(output.read_text())["targets"]
    assert [target["model"] for target in targets] == ["cmp-l", "cmp-l-azure"]
    assert [target["machine_type"] for target in targets] == [
        "a3-highgpu-1g",
        "Standard_NCC40ads_H100_v5",
    ]
    assert [target["podvm_image_tag"] for target in targets] == [
        "podvm-gcp",
        "podvm-azure",
    ]
    assert all("provider" not in target for target in targets)
    assert all(target["sources"] == [TEST_SHA] for target in targets)
    expected_initdata = b"policy = 'cmp-l-cc'\n"
    expected_digest = hashlib.sha384(expected_initdata).hexdigest()
    assert targets[0]["initdata_sha384"] == expected_digest
    assert targets[0]["initdata_file"] == f"initdata/{expected_digest}.toml"
    assert (tmp_path / targets[0]["initdata_file"]).read_bytes() == expected_initdata
    assert derive.DEFAULT_GENERATED_DIR == "k8s/geofence-models/base/generated"

    list_call = calls[0]
    assert list_call[0] == [
        str(tmp_path / derive.LIST_MODELS_SCRIPT),
        "--confidential",
    ]
    assert list_call[1]["cwd"] == tmp_path / derive.BLOBHEART_MODELS_DIR
    build_calls = [call for call in calls if call[0][:2] == ["kustomize", "build"]]
    assert [Path(call[0][2]).name for call in build_calls] == list(builds)
    assert all(len(call[0]) == 3 for call in build_calls)
    assert all(call[1]["cwd"] == tmp_path for call in build_calls)
    assert not any(call[0][0] == "gh" for call in calls)


@pytest.mark.parametrize(
    ("missing", "expected_field"),
    [
        ("provider", "cohere.com/provider"),
        ("machine_type", "hypervisor.machine_type"),
        ("image", "hypervisor.image"),
        ("initdata", "hypervisor.cc_init_data"),
        ("runtime_class", "runtimeClassName"),
    ],
)
def test_derive_rejects_missing_rendered_fields(
    missing,
    expected_field,
    tmp_path,
    monkeypatch,
    capsys,
):
    derive = load_action(
        f"derive_manifest_missing_{missing}",
        ".github/actions/derive-manifest/derive.py",
    )
    kwargs = {missing: None}
    output = tmp_path / "manifest.yaml"

    with pytest.raises(SystemExit, match="1"):
        run_local_derive(
            derive,
            tmp_path,
            output,
            monkeypatch,
            listed=["cmp-l-cc"],
            builds={"cmp-l-cc": rendered_cc_model("cmp-l-cc", **kwargs)},
        )

    error = capsys.readouterr().err
    assert "cmp-l-cc" in error
    assert expected_field in error
    assert not output.exists()


@pytest.mark.parametrize(
    ("rendered", "expected_count"),
    [
        (rendered_cc_model("cmp-l-cc", confidential=False), 0),
        (rendered_cc_model("cmp-l-cc", workload_count=2), 2),
    ],
)
def test_derive_requires_exactly_one_confidential_statefulset(
    rendered,
    expected_count,
    tmp_path,
    monkeypatch,
    capsys,
):
    derive = load_action(
        f"derive_manifest_workload_count_{expected_count}",
        ".github/actions/derive-manifest/derive.py",
    )

    with pytest.raises(SystemExit, match="1"):
        run_local_derive(
            derive,
            tmp_path,
            tmp_path / "manifest.yaml",
            monkeypatch,
            listed=["cmp-l-cc"],
            builds={"cmp-l-cc": rendered},
        )

    error = capsys.readouterr().err
    assert "cmp-l-cc" in error
    assert "cohere.com/confidential-compute" in error
    assert f"found {expected_count}" in error


def test_derive_rejects_azure_image_without_gallery_definition(
    tmp_path, monkeypatch, capsys
):
    """An Azure image ref must name a gallery definition, not just a tag.

    The published OCI tag is the gallery image definition, which sits mid-path.
    Accepting a bare registry path would silently derive the wrong tag and fail
    later, during policy generation, as an unresolvable artifact pull.
    """
    derive = load_action(
        "derive_manifest_azure_image_shape",
        ".github/actions/derive-manifest/derive.py",
    )
    rendered = rendered_cc_model(
        "cmp-l-azure-cc",
        provider="azure",
        runtime_class="kata-remote-azure",
        machine_type="Standard_NCC40ads_H100_v5",
        image="registry.example/azure/podvm-azure",
    )

    with pytest.raises(SystemExit, match="1"):
        run_local_derive(
            derive,
            tmp_path,
            tmp_path / "manifest.yaml",
            monkeypatch,
            listed=["cmp-l-azure-cc"],
            builds={"cmp-l-azure-cc": rendered},
        )

    error = capsys.readouterr().err
    assert "cmp-l-azure-cc" in error
    assert "Azure gallery image ID" in error


def test_derive_rejects_runtime_provider_mismatch(tmp_path, monkeypatch, capsys):
    derive = load_action(
        "derive_manifest_runtime_provider_mismatch",
        ".github/actions/derive-manifest/derive.py",
    )
    rendered = rendered_cc_model(
        "cmp-l-azure-cc",
        provider="azure",
        runtime_class="kata-remote",
        machine_type="Standard_NCC40ads_H100_v5",
    )

    with pytest.raises(SystemExit, match="1"):
        run_local_derive(
            derive,
            tmp_path,
            tmp_path / "manifest.yaml",
            monkeypatch,
            listed=["cmp-l-azure-cc"],
            builds={"cmp-l-azure-cc": rendered},
        )

    error = capsys.readouterr().err
    assert "cmp-l-azure-cc" in error
    assert "runtimeClassName" in error
    assert "kata-remote-azure" in error


@pytest.mark.parametrize(
    ("machine_type", "message"),
    [
        ("a3-highgpu-1g", "does not match"),
        ("unknown-machine", "unknown machine type"),
    ],
)
def test_derive_validates_machine_type_for_provider(
    machine_type,
    message,
    tmp_path,
    monkeypatch,
    capsys,
):
    derive = load_action(
        f"derive_manifest_machine_provider_{machine_type}",
        ".github/actions/derive-manifest/derive.py",
    )
    rendered = rendered_cc_model(
        "cmp-l-azure-cc",
        provider="azure",
        runtime_class="kata-remote-azure",
        machine_type=machine_type,
    )

    with pytest.raises(SystemExit, match="1"):
        run_local_derive(
            derive,
            tmp_path,
            tmp_path / "manifest.yaml",
            monkeypatch,
            listed=["cmp-l-azure-cc"],
            builds={"cmp-l-azure-cc": rendered},
        )

    error = capsys.readouterr().err
    assert "cmp-l-azure-cc" in error
    assert machine_type in error
    assert message in error


def test_derive_excludes_generated_model_not_returned_by_script(
    tmp_path,
    monkeypatch,
):
    derive = load_action(
        "derive_manifest_non_listed_excluded",
        ".github/actions/derive-manifest/derive.py",
    )
    builds = {
        "cmp-l-cc": rendered_cc_model("cmp-l-cc"),
        "unlisted-l-cc": "not: valid: yaml",
    }

    calls = run_local_derive(
        derive,
        tmp_path,
        tmp_path / "manifest.yaml",
        monkeypatch,
        listed=["cmp-l-cc"],
        builds=builds,
    )

    build_calls = [call for call in calls if call[0][:2] == ["kustomize", "build"]]
    assert [Path(call[0][2]).name for call in build_calls] == ["cmp-l-cc"]


def test_derive_rejects_listed_model_without_generated_directory(
    tmp_path,
    monkeypatch,
    capsys,
):
    derive = load_action(
        "derive_manifest_missing_generated_directory",
        ".github/actions/derive-manifest/derive.py",
    )
    calls = []

    with pytest.raises(SystemExit, match="1"):
        run_local_derive(
            derive,
            tmp_path,
            tmp_path / "manifest.yaml",
            monkeypatch,
            listed=["missing-l-cc"],
            existing_models=[],
            calls=calls,
        )

    assert "missing-l-cc" in capsys.readouterr().err
    assert not any(call[0][:2] == ["kustomize", "build"] for call in calls)


def test_derive_ignores_unrelated_attestation_annotation(tmp_path, monkeypatch):
    derive = load_action(
        "derive_manifest_ignores_attestation_mode",
        ".github/actions/derive-manifest/derive.py",
    )
    output = tmp_path / "manifest.yaml"

    run_local_derive(
        derive,
        tmp_path,
        output,
        monkeypatch,
        listed=["cmp-l-cc"],
        builds={
            "cmp-l-cc": rendered_cc_model(
                "cmp-l-cc", attestation_mode="no_ra"
            )
        },
    )

    assert yaml.safe_load(output.read_text())["targets"][0]["model"] == "cmp-l"


def test_derive_accepts_but_ignores_old_kustomization_path(
    tmp_path,
    monkeypatch,
    capsys,
):
    derive = load_action(
        "derive_manifest_deprecated_kustomization",
        ".github/actions/derive-manifest/derive.py",
    )
    output = tmp_path / "manifest.yaml"
    generated_dir = "custom/generated"

    calls = run_local_derive(
        derive,
        tmp_path,
        output,
        monkeypatch,
        listed=["cmp-l-cc"],
        builds={"cmp-l-cc": rendered_cc_model("cmp-l-cc")},
        generated_dir=generated_dir,
        extra_args=["--kustomization-path", "does/not/exist.yaml"],
    )

    assert "deprecated and ignored" in capsys.readouterr().err
    build_call = next(call for call in calls if call[0][0] == "kustomize")
    assert build_call[0] == [
        "kustomize",
        "build",
        f"{generated_dir}/cmp-l-cc",
    ]
    assert yaml.safe_load(output.read_text())["targets"][0]["model"] == "cmp-l"


def test_derive_preserves_empty_manifest_for_empty_script_output(
    tmp_path,
    monkeypatch,
):
    derive = load_action(
        "derive_manifest_empty",
        ".github/actions/derive-manifest/derive.py",
    )
    output = tmp_path / "manifest.yaml"

    calls = run_local_derive(
        derive,
        tmp_path,
        output,
        monkeypatch,
        list_output="",
    )

    assert yaml.safe_load(output.read_text()) == {"targets": []}
    assert not any(call[0][0] == "kustomize" for call in calls)


@pytest.mark.parametrize(
    ("output", "message"),
    [
        ("cmp-l-cc\ncmp-l-cc\n", "duplicate model ID"),
        ("cmp-l-cc other\n", "invalid model ID"),
        ("../cmp-l-cc\n", "invalid model ID"),
        ("cmp-l\n", "must end in '-cc'"),
    ],
)
def test_derive_validates_model_list_output(output, message):
    derive = load_action(
        f"derive_manifest_list_{message.split()[0]}",
        ".github/actions/derive-manifest/derive.py",
    )

    with pytest.raises(ValueError, match=message):
        derive.parse_model_list(output)


def test_derive_bounds_compressed_initdata_expansion():
    derive = load_action(
        "derive_manifest_bounded_initdata",
        ".github/actions/derive-manifest/derive.py",
    )
    content = b"x" * (derive.MAX_INITDATA_BYTES + 1)
    encoded = base64.b64encode(gzip.compress(content)).decode()

    with pytest.raises(ValueError, match="decoded cc_init_data exceeds"):
        derive.decode_initdata(encoded)


def test_derive_decodes_concatenated_gzip_initdata():
    derive = load_action(
        "derive_manifest_concatenated_initdata",
        ".github/actions/derive-manifest/derive.py",
    )
    encoded = base64.b64encode(
        gzip.compress(b"first") + gzip.compress(b"second")
    ).decode()

    assert derive.decode_initdata(encoded) == b"firstsecond"


def test_derive_rejects_malformed_gzip_initdata():
    derive = load_action(
        "derive_manifest_malformed_initdata",
        ".github/actions/derive-manifest/derive.py",
    )
    encoded = base64.b64encode(b"\x1f\x8bnot-gzip").decode()

    with pytest.raises(ValueError, match="invalid cc_init_data"):
        derive.decode_initdata(encoded)


def test_derivation_actions_pin_tools_and_use_current_layout():
    actions = [
        REPO_ROOT / ".github/actions/derive-manifest/action.yml",
        REPO_ROOT / ".github/actions/verify-against-policy/action.yml",
    ]
    for path in actions:
        action = yaml.safe_load(path.read_text())
        assert action["inputs"]["generated-dir"]["default"] == (
            "k8s/geofence-models/base/generated"
        )
        assert "default" not in action["inputs"]["kustomization-path"]
        assert action["runs"]["steps"][0]["name"] == (
            "Install policy derivation tools"
        )

    installer = (
        REPO_ROOT / ".github/actions/derive-manifest/install-tools.sh"
    ).read_text()
    assert 'KUSTOMIZE_VERSION="5.8.1"' in installer
    assert 'YQ_VERSION="4.44.3"' in installer
    assert installer.count("sha256sum --check --status") == 2


def test_derive_remote_source_uses_sparse_partial_checkout_at_exact_sha(
    tmp_path,
    monkeypatch,
):
    derive = load_action(
        "derive_manifest_remote_checkout",
        ".github/actions/derive-manifest/derive.py",
    )
    destination = tmp_path / "blobheart"
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return f"{TEST_SHA}\n" if command[-2:] == ["rev-parse", "HEAD"] else ""

    monkeypatch.setattr(derive, "run_command", fake_run)

    assert derive.checkout_remote_ref(TEST_SHA, destination) == destination
    assert calls[0][0] == [
        "gh",
        "repo",
        "clone",
        derive.BLOBHEART_REPO,
        str(destination),
        "--",
        "--filter=blob:none",
        "--no-checkout",
    ]
    git_prefix = ["git", "-C", str(destination)]
    assert [call[0] for call in calls[1:]] == [
        git_prefix
        + ["sparse-checkout", "set", str(derive.BLOBHEART_MODELS_DIR)],
        git_prefix + ["fetch", "--depth=1", "origin", TEST_SHA],
        git_prefix + ["checkout", "--detach", TEST_SHA],
        git_prefix + ["rev-parse", "HEAD"],
    ]
    assert all(
        "gh auth git-credential" in " ".join(call[1]["env"].values())
        for call in calls[1:]
    )


def test_derive_remote_source_rejects_unexpected_checked_out_sha(
    tmp_path,
    monkeypatch,
):
    derive = load_action(
        "derive_manifest_remote_checkout_mismatch",
        ".github/actions/derive-manifest/derive.py",
    )

    def fake_run(command, **_kwargs):
        return f"{'b' * 40}\n" if command[-2:] == ["rev-parse", "HEAD"] else ""

    monkeypatch.setattr(derive, "run_command", fake_run)

    with pytest.raises(RuntimeError, match=f"expected {TEST_SHA}"):
        derive.checkout_remote_ref(TEST_SHA, tmp_path / "blobheart")


def test_local_derivation_uses_checkout_commit(monkeypatch, tmp_path):
    derive = load_action(
        "derive_manifest_local_ref",
        ".github/actions/derive-manifest/derive.py",
    )
    run = Mock(returncode=0, stdout=f"{TEST_SHA}\n", stderr="")
    monkeypatch.setattr(derive.subprocess, "run", Mock(return_value=run))

    assert derive.resolve_local_ref(tmp_path) == TEST_SHA


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
