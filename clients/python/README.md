# Model Integrity Client

Python client for Cohere's model integrity ledger.

## Installation

```bash
pip install model-integrity-client
```

## Usage

```python
from model_integrity import ModelIntegrityClient

client = ModelIntegrityClient()

# Full verification flow (discovery -> download -> verify -> extract)
attestation = client.get_verified_attestation(
    model="command-r-plus",
    known_log_index=None,  # None for first run, previous index after that
)

print(f"Policy ID: {attestation.policy_id}")
print(f"Measurements: {attestation.measurements}")
print(f"Release: {attestation.release_tag}")
```

## For TNG Integration

TNG should:
1. Call `get_verified_attestation()` on startup and periodically
2. Use the returned `policy_id` for ITA token requests
3. Store the Rekor log index from the predicate for chain verification
4. On verification failure, reject the update and keep the previous known-good state
