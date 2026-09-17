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
                       PodVM image + initdata (+ OVMF and baseline, TDX only)
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
     cvm-measure tdx ─► MRTD + RTMR[0-3]   cvm-measure azure-snp ─► vTPM PCR 4/5/8/9/11
                    │                                 │
                    ▼                                 ▼
             ita_policy.rego                trustee_policy_{cpu,gpu}.rego
                    │                                 │
                    ▼                                 │
      Upload to ITA ─► policy_id                      │
                    │                                 │
                    └────────────────┬────────────────┘
                                     ▼
                    in-toto attestation (measurements + policies + chain)
                                     │
                                     ▼
                        Sigstore keyless sign ─► Rekor entry
                                     │
                                     ▼
                       GitHub Release with all artifacts
```

The two branches differ in where the policy ends up, not in how it is built.
The ITA policy is uploaded and referenced by id; the Trustee pair is only ever
released for Trustee AS consumption. Both are covered by the same signed 
attestation.

### Using the Trustee policies

Download `trustee_policy_cpu.rego` and `trustee_policy_gpu.rego` into one
directory and use the Trustee attestation service with
`policy_ids: ["trustee_policy"]`.

## For Auditors

Every release contains:

- `ita_policy.rego` -- the composite ITA appraisal policy that was uploaded
- `trustee_policy_cpu.rego` -- the Trustee CPU appraisal policy, for Azure SEV-SNP
- `trustee_policy_gpu.rego` -- the Trustee GPU appraisal policy (uses NRAS)
- `policy-manifest.yaml` -- every workload the policies cover
- `policy-manifest-bundle.tar.gz` -- the manifest plus its content-addressed initdata
- `predicate.json` -- in-toto predicate: per-target measurements and baseline refs,
  `cvm_measure_version`, the `policy_id`, how many targets each policy covers,
  a `trustee_policies` block with each file's digest and the Azure platform
  reference values it accepts, the manifest commit, and the chain link
- `attestation-bundle.sigstore.json` -- one Sigstore bundle over all three
  policies and the manifest, verifiable against public Rekor

The Azure policy pins exact `cvm-measure` references with no degrade path. A
reboot lets `systemd-repart` rewrite the partition UUID, which moves PCR 5 and
is expected to fail attestation; pod VMs are created per pod and destroyed, so
first boot is the normal case.

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
    policy-types: ita trustee    # space- or comma-separated: ita, trustee
    predicate-file: predicate.json
```

The action writes to `generated-policies/` in the workspace and reports
`ita-policy-file`, `trustee-cpu-policy-file`, `trustee-gpu-policy-file`,
`trustee-policy-dir` and a target count per type, so every later step reads a
path the generator wrote rather than a literal it has to keep in agreement.
Reported paths are workspace-relative, since the action runs in a container
where the workspace is `/github/workspace` and the steps that consume them do
not. Filenames are the action's to choose because Trustee resolves them by name;
the directory is cleared before each run, so a type left out of `policy-types`
cannot leave a stale policy behind to be attested as current.

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
  would fail for it. The Trustee renderer maps the pair to a verifier -- today
  `(azure, snp)` to `az-snp-vtpm` -- and skips a pair it has no section for.
- `ram_gib` feeds `cvm-measure tdx --ram`, since MRTD covers the RAM topology
  through the TD Handover Block.

Adding an entry does not create a policy target. Targets come from the manifest;
the table is consulted only for the machine types they name, and an unknown one
fails generation.

Adding a platform means a row here plus, for Trustee, confirming which verifier
upstream routes that evidence to. The key cannot be inferred from the pair:
`(azure, tdx)` would take `az-tdx-vtpm` rather than `tdx`, because a vTPM
platform emits PCRs alongside the TD quote, which is a different claim shape
rather than different values.

No target says which attestation service it belongs to, deliberately. That
choice lives in policy consumer configuration and nothing in the podspec
exposes it, so each policy enumerates every target whose hardware it can
appraise. A target listed in a policy nothing currently exercises is inert
rather than dangerous: these policies are permissive by enumeration, so an
accepted value matches nothing unless something presents evidence for it.

### Editing the templates

The ITA template renders through a restricted Rego subset that ITA enforces,
so plain OPA accepting a construct proves nothing. Prefer using constructs 
with release history.

The Trustee templates render through regorus, which rejects any line over 1024
columns in the lexer, before parsing. Every multi-value set is therefore
emitted one element per line: an inline literal passes at four entries and
breaches silently at roughly fifteen.


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
        trustee.py                # Trustee renderer
        trustee-cpu-template.rego # Trustee CPU policy template
        trustee-gpu-template.rego # Trustee GPU policy template
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
