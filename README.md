# Integritee

Public integrity ledger for Cohere's confidential computing models.

This repository contains:

- **Policy manifest and initdata** (`attestation-policy/`) -- content-addressed
  workload inputs imported from Blobheart
- **Policy automation actions** (`.github/actions/`) -- derive, validate,
  measure, upload, and verify policies
- **CI workflow** (`.github/workflows/release-policy.yaml`) -- automated pipeline that generates policies, computes measurements, uploads to Intel Trust Authority, and publishes Sigstore-signed releases

## How It Works

```
Blobheart podspec ─► genpolicy ─► Kata policy + initdata
                                     │
                                     ▼
              OVMF + UKI + baseline + initdata ─► cvm-measure ─► MRTD + RTMR[0-3]
                                                                       │
                                                                       ▼
                                         ITA attestation policy template + measurements
                                                                       │
                                                                       ▼
                                                        Upload to ITA ─► policy_id
                                                                       │
                                                                       ▼
                                              in-toto attestation (measurements + policy + chain)
                                                                       │
                                                                       ▼
                                                    Sigstore keyless sign ─► Rekor entry
                                                                       │
                                                                       ▼
                                                         GitHub Release with all artifacts
```

## For TNG Operators

TNG discovers the latest policy by fetching the latest GitHub release:

```
GET /repos/cohere-ai/integritee/releases/latest
```

Then downloads `attestation-bundle.sigstore.json` and verifies the Sigstore bundle
locally before extracting the `policy_id` for ITA token requests. The verified
predicate is the authoritative source for the policy ID; consumers should read it
from there rather than hardcoding it.

## For Auditors

Every release contains:

- `attestation-policy.rego` -- the composite ITA appraisal policy that was uploaded
- `policy-manifest.yaml` -- every workload the policy covers
- `policy-manifest-bundle.tar.gz` -- the manifest plus its content-addressed initdata
- `predicate.json` -- in-toto predicate: per-target measurements and baseline refs,
  `cvm_measure_version`, the `policy_id`, the manifest commit, and the chain link
- `attestation-bundle.sigstore.json` -- Sigstore bundle over `attestation-policy.rego`,
  verifiable against public Rekor

The predicate includes a `previous_rekor_log_index` field that chains releases
together, forming a linked list in the public Rekor transparency log.

## Repository Structure

```
attestation-policy/
  policy-manifest.yaml            # Workloads included in the policy
  initdata/                       # Content-addressed workload initdata
.github/
  actions/                        # Policy automation actions
  workflows/
    release-policy.yaml           # Main attestation workflow
```

## Triggering a Release

```bash
gh workflow run release-policy.yaml \
  -f version=v0.0.1 \
  -f reason="Updated container image for command-r-plus"
```

## License

Apache License 2.0
