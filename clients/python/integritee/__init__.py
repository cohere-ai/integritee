"""Integritee client library.

Provides TNG (and other consumers) with:
- Discovery: fetch the latest GitHub release for a model
- Verification: validate the Sigstore bundle against public Rekor
- Extraction: pull the policy_id from the verified predicate
"""

from integritee.client import (
    IntegriteeClient,
    ReleaseInfo,
    VerifiedAttestation,
)

__all__ = [
    "IntegriteeClient",
    "ReleaseInfo",
    "VerifiedAttestation",
]
