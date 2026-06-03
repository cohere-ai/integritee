# Integritee

Public integrity ledger for Cohere's confidential computing models.

This repository contains:

- **Model manifests** (`models/`) -- Kubernetes podspecs for each confidential model
- **Kata policy rules** (`rules/`) -- shared OPA Rego rules and genpolicy settings
- **Attestation policy templates** (`attestation-policy/`) -- base ITA policy templates
- **CI workflow** (`.github/workflows/attest-model.yaml`) -- automated pipeline that generates policies, computes measurements, uploads to Intel Trust Authority, and publishes Sigstore-signed releases

## How It Works

```
podspec.yaml ─► genpolicy ─► Kata policy + initdata
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

Then downloads `{model}/attestation.sigstore.json` and verifies the Sigstore bundle
locally before extracting the `policy_id` for ITA token requests.

## For Auditors

Every release contains per-model artifacts:

- `{model}/measurements.json` -- expected TDX register values (MRTD, RTMR[0-3])
- `{model}/kata-policy.rego` -- full Kata agent policy text
- `{model}/predicate.json` -- complete in-toto predicate with all metadata
- `{model}/attestation.sigstore.json` -- Sigstore bundle (verifiable against public Rekor)

Each model's Sigstore attestation includes a `previous_rekor_log_index` field that
chains entries together, forming a per-model linked list in the public Rekor transparency log.

## Repository Structure

```
models/
  command-r-plus/
    podspec.yaml                  # K8s manifest with kata-remote runtime
    genpolicy-settings.json       # Optional: model-specific genpolicy overrides
    rules.rego                    # Optional: model-specific rules overrides
rules/
  rules.rego                      # Shared Kata OPA rules (~2000 lines)
  genpolicy-settings.json         # Base genpolicy settings
attestation-policy/
  template.rego                   # Base ITA attestation policy template
scripts/
  generate-ita-policy.py          # Generates ITA policy from template + measurements
  build-predicate.py              # Builds the in-toto predicate JSON
.github/
  workflows/
    attest-model.yaml             # Main attestation workflow
```

## Triggering a Release

```bash
gh workflow run attest-model.yaml \
  -f version=v0.0.1 \
  -f reason="Updated container image for command-r-plus"
```

## License

Apache License 2.0
