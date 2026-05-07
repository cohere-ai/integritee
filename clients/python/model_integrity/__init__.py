"""Model Integrity client library.

Provides TNG (and other consumers) with:
- Discovery: fetch the latest GitHub release for a model
- Verification: validate the Sigstore bundle against public Rekor
- Extraction: pull the policy_id from the verified predicate
"""

from model_integrity.client import (
    ModelIntegrityClient,
    ReleaseInfo,
    VerifiedAttestation,
)

__all__ = [
    "ModelIntegrityClient",
    "ReleaseInfo",
    "VerifiedAttestation",
]
