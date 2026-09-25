"""Policy-manifest versioning and target validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

MANIFEST_SCHEMA_PATH = Path(__file__).with_name(
    "policy-manifest-v1.schema.json"
)
MACHINE_TYPES_PATH = Path(__file__).with_name("machine-types.yaml")
MANIFEST_SCHEMA = json.loads(MANIFEST_SCHEMA_PATH.read_text())
SCHEMA_VERSION: int = MANIFEST_SCHEMA["properties"]["schema_version"]["const"]
MANIFEST_TARGET_FIELDS = tuple(
    MANIFEST_SCHEMA["$defs"]["target"]["properties"]
)

TARGET_CONTENT_FIELDS = (
    "model",
    "provider",
    "machine_type",
    "podvm_image_tag",
    "initdata_sha384",
)
PROVIDER_RUNTIMES = {
    "gcp": "kata-remote",
    "azure": "kata-remote-azure",
}


def load_machine_types() -> dict[str, dict]:
    return yaml.safe_load(MACHINE_TYPES_PATH.read_text()) or {}


def schema_errors(document: object) -> list[str]:
    """Return readable structural errors for a schema-v1 manifest."""
    from jsonschema import Draft202012Validator

    errors = sorted(
        Draft202012Validator(MANIFEST_SCHEMA).iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    formatted: list[str] = []
    for error in errors:
        path = ".".join(str(part) for part in error.absolute_path)
        location = f"manifest.{path}" if path else "manifest"
        formatted.append(f"{location}: {error.message}")
    return formatted


def schema_version(document: object) -> int:
    """Return 0 for a legacy manifest or validate the current version."""
    if not isinstance(document, dict):
        raise ValueError("manifest must be a mapping")

    if "schema_version" not in document:
        return 0
    version = document["schema_version"]
    if type(version) is not int or version != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported manifest schema_version {version!r}; "
            f"expected {SCHEMA_VERSION}"
        )

    return version


def manifest_targets(document: object) -> tuple[int, list[dict]]:
    """Validate and return a manifest's schema version and targets."""
    version = schema_version(document)
    if version == SCHEMA_VERSION:
        errors = schema_errors(document)
        if errors:
            raise ValueError("; ".join(errors))
    targets = document.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("manifest targets must be a non-empty list")
    if any(not isinstance(target, dict) for target in targets):
        raise ValueError("every manifest target must be a mapping")
    return version, targets


def target_content_hash(target: dict) -> str:
    """Hash the fields that define a policy target."""
    values = [str(target.get(field, "")) for field in TARGET_CONTENT_FIELDS]
    payload = json.dumps(values, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def target_provider(
    target: dict,
    machine_types: dict[str, dict],
    version: int,
) -> str:
    """Resolve and validate a target's provider at the manifest read boundary."""
    machine_type = target.get("machine_type")
    if not isinstance(machine_type, str) or not machine_type:
        raise ValueError("machine_type must be a non-empty string")
    machine = machine_types.get(machine_type)
    if machine is None:
        raise ValueError(f"unknown machine_type {machine_type!r}")

    provider = target.get("provider")
    if version == SCHEMA_VERSION and not provider:
        raise ValueError(
            f"provider is required by manifest schema v{SCHEMA_VERSION}"
        )
    if provider is None:
        provider = machine["platform"]
    if not isinstance(provider, str) or not provider:
        raise ValueError("provider must be a non-empty string")
    if provider not in PROVIDER_RUNTIMES:
        raise ValueError(f"unsupported provider {provider!r}")
    if provider != machine["platform"]:
        raise ValueError(
            f"provider {provider!r} does not match machine_type "
            f"{machine_type!r} platform {machine['platform']!r}"
        )
    return provider
