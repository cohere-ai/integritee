"""TNG-side client for discovering and verifying model integrity.

Fetches the latest GitHub Release, downloads per-model artifacts,
verifies the Sigstore bundle locally, and extracts the policy_id
for use in ITA token requests.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
DEFAULT_REPO = "cohere-ai/model-integrity"
EXPECTED_WORKFLOW_REF = (
    "https://github.com/cohere-ai/model-integrity/"
    ".github/workflows/attest-model.yaml@refs/heads/main"
)
EXPECTED_ISSUER = "https://token.actions.githubusercontent.com"


@dataclass
class ReleaseInfo:
    """Metadata about a GitHub Release."""

    tag: str
    url: str
    assets: dict[str, str] = field(default_factory=dict)


@dataclass
class VerifiedAttestation:
    """Result of a successful Sigstore verification."""

    model: str
    policy_id: str
    measurements: dict[str, str]
    predicate: dict[str, Any]
    release_tag: str
    rekor_log_index: int | None = None


class VerificationError(Exception):
    """Raised when Sigstore verification fails."""


class ModelIntegrityClient:
    """Client for fetching and verifying model integrity attestations."""

    def __init__(
        self,
        repo: str = DEFAULT_REPO,
        github_token: str | None = None,
        cosign_path: str = "cosign",
        expected_issuer: str = EXPECTED_ISSUER,
        expected_identity: str = EXPECTED_WORKFLOW_REF,
    ) -> None:
        self._repo = repo
        self._github_token = github_token
        self._cosign_path = cosign_path
        self._expected_issuer = expected_issuer
        self._expected_identity = expected_identity

    def _github_request(self, path: str) -> Any:
        url = f"{GITHUB_API}{path}"
        req = Request(url)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if self._github_token:
            req.add_header("Authorization", f"Bearer {self._github_token}")

        with urlopen(req) as resp:
            return json.loads(resp.read())

    def _download_asset(self, url: str) -> bytes:
        req = Request(url)
        req.add_header("Accept", "application/octet-stream")
        if self._github_token:
            req.add_header("Authorization", f"Bearer {self._github_token}")

        with urlopen(req) as resp:
            return resp.read()

    def get_latest_release(self) -> ReleaseInfo:
        """Fetch the latest release from the repo."""
        data = self._github_request(f"/repos/{self._repo}/releases/latest")

        assets: dict[str, str] = {}
        for asset in data.get("assets", []):
            assets[asset["name"]] = asset["browser_download_url"]

        return ReleaseInfo(
            tag=data["tag_name"],
            url=data["html_url"],
            assets=assets,
        )

    def get_model_assets(self, release: ReleaseInfo, model: str) -> dict[str, str]:
        """Filter release assets for a specific model (prefix match)."""
        prefix = f"{model}/"
        return {
            name: url
            for name, url in release.assets.items()
            if name.startswith(prefix)
        }

    def download_model_artifacts(
        self, release: ReleaseInfo, model: str, dest: Path
    ) -> dict[str, Path]:
        """Download all artifacts for a model from a release."""
        assets = self.get_model_assets(release, model)
        if not assets:
            raise FileNotFoundError(
                f"No assets found for model '{model}' in release {release.tag}"
            )

        dest.mkdir(parents=True, exist_ok=True)
        downloaded: dict[str, Path] = {}

        for name, url in assets.items():
            filename = name.split("/", 1)[-1]
            filepath = dest / filename
            logger.info("Downloading %s -> %s", name, filepath)
            filepath.write_bytes(self._download_asset(url))
            downloaded[filename] = filepath

        return downloaded

    def verify_bundle(
        self,
        measurements_path: Path,
        bundle_path: Path,
    ) -> dict:
        """Verify a Sigstore bundle using cosign.

        Checks:
        - Signature validity
        - Signer identity (must be the expected GitHub Actions workflow)
        - Rekor inclusion proof

        Returns the verified attestation predicate.
        """
        cmd = [
            self._cosign_path,
            "verify-blob-attestation",
            "--bundle", str(bundle_path),
            "--certificate-oidc-issuer", self._expected_issuer,
            "--certificate-identity", self._expected_identity,
            str(measurements_path),
        ]

        logger.info("Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise VerificationError(
                f"Sigstore verification failed:\n{e.stderr}"
            ) from e

        for line in result.stdout.strip().splitlines():
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue

        logger.warning(
            "Could not parse attestation from cosign output, "
            "falling back to reading predicate from bundle directly"
        )
        return self._extract_predicate_from_bundle(bundle_path)

    def _extract_predicate_from_bundle(self, bundle_path: Path) -> dict:
        """Extract predicate from a Sigstore bundle file."""
        import base64

        bundle = json.loads(bundle_path.read_text())

        dsse_envelope = bundle.get("dsseEnvelope", {})
        payload_b64 = dsse_envelope.get("payload", "")
        if payload_b64:
            payload = json.loads(base64.b64decode(payload_b64))
            return payload.get("predicate", payload)

        return {}

    def verify_chain(
        self,
        predicate: dict,
        known_log_index: int | None,
    ) -> bool:
        """Verify chain linking: previous_rekor_log_index matches our known state.

        If known_log_index is None (first run), any value is accepted.
        """
        prev = predicate.get("previous_rekor_log_index")
        if prev is None:
            logger.warning("Predicate missing previous_rekor_log_index")
            return False

        if known_log_index is None:
            logger.info("First run, accepting previous_rekor_log_index=%d", prev)
            return True

        if prev != known_log_index:
            logger.error(
                "Chain break: expected previous_rekor_log_index=%d, got %d",
                known_log_index,
                prev,
            )
            return False

        return True

    def get_verified_attestation(
        self,
        model: str,
        known_log_index: int | None = None,
    ) -> VerifiedAttestation:
        """Full flow: discover -> download -> verify -> extract.

        This is the main entry point TNG should call.
        """
        release = self.get_latest_release()
        logger.info("Latest release: %s", release.tag)

        with tempfile.TemporaryDirectory(prefix="model-integrity-") as tmpdir:
            dest = Path(tmpdir)
            artifacts = self.download_model_artifacts(release, model, dest)

            measurements_path = artifacts.get("measurements.json")
            bundle_path = artifacts.get("attestation.sigstore.json")

            if not measurements_path or not bundle_path:
                raise FileNotFoundError(
                    f"Release {release.tag} missing required artifacts for {model}. "
                    f"Found: {list(artifacts.keys())}"
                )

            predicate = self.verify_bundle(measurements_path, bundle_path)

            if not self.verify_chain(predicate, known_log_index):
                raise VerificationError(
                    f"Chain verification failed for {model}. "
                    f"Expected previous_rekor_log_index={known_log_index}, "
                    f"got {predicate.get('previous_rekor_log_index')}"
                )

            measurements = predicate.get("measurements", {})
            policy_id = predicate.get("policy_id", "")

            if not policy_id:
                raise VerificationError(
                    f"Verified predicate for {model} has no policy_id"
                )

            return VerifiedAttestation(
                model=model,
                policy_id=policy_id,
                measurements=measurements,
                predicate=predicate,
                release_tag=release.tag,
            )
