"""Tests for the TNG client library.

Tests the ModelIntegrityClient's verification and chain-checking logic
using locally-constructed test data.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

# Add client library to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "clients" / "python"))

from model_integrity.client import (
    ModelIntegrityClient,
    ReleaseInfo,
    VerificationError,
    VerifiedAttestation,
)


@pytest.fixture
def client() -> ModelIntegrityClient:
    return ModelIntegrityClient(
        repo="cohere-ai/model-integrity",
        cosign_path="cosign",
    )


@pytest.fixture
def sample_release() -> ReleaseInfo:
    return ReleaseInfo(
        tag="v0.0.1",
        url="https://github.com/cohere-ai/model-integrity/releases/tag/v0.0.1",
        assets={
            "command-r-plus/measurements.json": "https://example.com/meas.json",
            "command-r-plus/attestation.sigstore.json": "https://example.com/attest.json",
            "command-r-plus/predicate.json": "https://example.com/pred.json",
            "aya-expanse/measurements.json": "https://example.com/aya-meas.json",
        },
    )


class TestReleaseDiscovery:
    """Test release asset filtering and model matching."""

    def test_get_model_assets_filters_by_prefix(
        self, client: ModelIntegrityClient, sample_release: ReleaseInfo
    ):
        assets = client.get_model_assets(sample_release, "command-r-plus")
        assert len(assets) == 3
        assert all(k.startswith("command-r-plus/") for k in assets)

    def test_get_model_assets_different_model(
        self, client: ModelIntegrityClient, sample_release: ReleaseInfo
    ):
        assets = client.get_model_assets(sample_release, "aya-expanse")
        assert len(assets) == 1
        assert "aya-expanse/measurements.json" in assets

    def test_get_model_assets_unknown_model(
        self, client: ModelIntegrityClient, sample_release: ReleaseInfo
    ):
        assets = client.get_model_assets(sample_release, "nonexistent-model")
        assert len(assets) == 0

    def test_release_info_structure(self, sample_release: ReleaseInfo):
        assert sample_release.tag == "v0.0.1"
        assert "github.com" in sample_release.url
        assert len(sample_release.assets) == 4


class TestChainVerification:
    """Test the chain linking verification logic."""

    def test_genesis_entry_accepted(self, client: ModelIntegrityClient):
        predicate = {"previous_rekor_log_index": 0}
        assert client.verify_chain(predicate, known_log_index=None) is True

    def test_matching_chain_accepted(self, client: ModelIntegrityClient):
        predicate = {"previous_rekor_log_index": 42}
        assert client.verify_chain(predicate, known_log_index=42) is True

    def test_mismatched_chain_rejected(self, client: ModelIntegrityClient):
        predicate = {"previous_rekor_log_index": 99}
        assert client.verify_chain(predicate, known_log_index=42) is False

    def test_missing_field_rejected(self, client: ModelIntegrityClient):
        predicate = {}
        assert client.verify_chain(predicate, known_log_index=42) is False

    def test_first_run_accepts_any_index(self, client: ModelIntegrityClient):
        predicate = {"previous_rekor_log_index": 12345}
        assert client.verify_chain(predicate, known_log_index=None) is True

    def test_zero_to_zero_chain(self, client: ModelIntegrityClient):
        """Genesis entry where known state is also 0."""
        predicate = {"previous_rekor_log_index": 0}
        assert client.verify_chain(predicate, known_log_index=0) is True


class TestBundleParsing:
    """Test Sigstore bundle predicate extraction."""

    def test_extract_predicate_from_dsse_bundle(
        self, client: ModelIntegrityClient, tmp_path: Path
    ):
        import base64

        predicate = {
            "model_path": "test-model",
            "policy_id": "abc-123",
            "measurements": {"mrtd": "a" * 96},
        }
        in_toto = {
            "predicateType": "https://cohere.com/attestation-policy-ledger/v1",
            "predicate": predicate,
        }
        payload_b64 = base64.b64encode(json.dumps(in_toto).encode()).decode()

        bundle = {
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": payload_b64,
                "signatures": [{"sig": "fakesig"}],
            }
        }

        bundle_path = tmp_path / "test.sigstore.json"
        bundle_path.write_text(json.dumps(bundle))

        extracted = client._extract_predicate_from_bundle(bundle_path)
        assert extracted["model_path"] == "test-model"
        assert extracted["policy_id"] == "abc-123"

    def test_extract_from_empty_bundle_returns_empty(
        self, client: ModelIntegrityClient, tmp_path: Path
    ):
        bundle_path = tmp_path / "empty.sigstore.json"
        bundle_path.write_text(json.dumps({}))

        result = client._extract_predicate_from_bundle(bundle_path)
        assert result == {}


class TestVerifiedAttestation:
    """Test the VerifiedAttestation dataclass."""

    def test_construction(self, real_measurements: dict):
        att = VerifiedAttestation(
            model="command-r-plus",
            policy_id="e34efa4e-9dde-4c6b-994f-0e95d3bce4ce",
            measurements=real_measurements,
            predicate={"model_path": "command-r-plus"},
            release_tag="v0.0.1",
            rekor_log_index=12345,
        )
        assert att.model == "command-r-plus"
        assert att.policy_id == "e34efa4e-9dde-4c6b-994f-0e95d3bce4ce"
        assert att.release_tag == "v0.0.1"
        assert att.rekor_log_index == 12345

    def test_default_rekor_index_is_none(self, real_measurements: dict):
        att = VerifiedAttestation(
            model="test",
            policy_id="id",
            measurements=real_measurements,
            predicate={},
            release_tag="v0.0.1",
        )
        assert att.rekor_log_index is None


class TestClientConfiguration:
    """Test client initialization and configuration."""

    def test_default_repo(self):
        c = ModelIntegrityClient()
        assert c._repo == "cohere-ai/model-integrity"

    def test_custom_repo(self):
        c = ModelIntegrityClient(repo="org/other-repo")
        assert c._repo == "org/other-repo"

    def test_custom_cosign_path(self):
        c = ModelIntegrityClient(cosign_path="/usr/local/bin/cosign")
        assert c._cosign_path == "/usr/local/bin/cosign"

    def test_custom_identity(self):
        c = ModelIntegrityClient(
            expected_identity="https://github.com/org/repo/.github/workflows/w.yaml@refs/heads/main"
        )
        assert "org/repo" in c._expected_identity
