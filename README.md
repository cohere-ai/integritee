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

- `ita_policy.rego` -- the composite ITA appraisal policy that was uploaded
- `policy-manifest.yaml` -- every workload the policy covers
- `policy-manifest-bundle.tar.gz` -- the manifest plus its content-addressed initdata
- `predicate.json` -- in-toto predicate: per-target measurements and baseline refs,
  `cvm_measure_version`, the `policy_id`, how many targets each policy covers,
  the manifest commit, and the chain link
- `attestation-bundle.sigstore.json` -- Sigstore bundle over `ita_policy.rego`,
  verifiable against public Rekor

The predicate includes a `previous_rekor_log_index` field that chains releases
together, forming a linked list in the public Rekor transparency log.

## Generating Policies

`.github/actions/generate-policy` reads the manifest, measures every target it
can appraise, and renders one Rego policy per attestation service. Callers
choose which services to generate for and pass no output path:

```yaml
- id: generate
  uses: ./.github/actions/generate-policy
  with:
    manifest-file: attestation-policy/policy-manifest.yaml
    github-token: ${{ steps.app-token.outputs.token }}
    output-artifacts-dir: artifacts
    policy-types: ita            # space- or comma-separated; ita is the only value today
    predicate-file: predicate.json
```

The action writes to `generated-policies/` in the workspace and reports
`ita-policy-file` and `ita-target-count`, so every later step reads a path the
generator wrote rather than a literal it has to keep in agreement.

A requested policy is always written, even when it matched no target -- an
empty policy admits nothing, which is what revoking withdrawn targets looks
like. The run fails only when *no* requested type matched anything, since then
no policy it produced could admit a node at all.

### Machine types

Hardware facts live in
`.github/actions/generate-policy/generate_policy/machine-types.yaml`, keyed by
the manifest's `machine_type` rather than repeated on every target:

- `platform` (`gcp`, `azure`) and `tee` (`tdx`, `snp`) decide which policies can
  appraise a target. ITA appraises TDX evidence, so a target on anything else is
  skipped with a notice instead of measured, before any baseline lookup that
  would fail for it.
- `ram_gib` feeds `cvm-measure tdx --ram`, since MRTD covers the RAM topology
  through the TD Handover Block.

Adding an entry does not create a policy target. Targets come from the manifest;
the table is consulted only for the machine types they name, and an unknown one
fails generation.


## Repository Structure

```
attestation-policy/
  policy-manifest.yaml            # Workloads included in the policy
  initdata/                       # Content-addressed workload initdata
.github/
  actions/                        # Policy automation actions
    generate-policy/
      generate_policy/
        generate.py               # Shared pipeline: manifest, machine types, PodVM, predicate
        ita.py                    # ITA renderer
        ita-template.rego         # ITA policy template
        machine-types.yaml        # Hardware facts per machine type
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
