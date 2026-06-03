# Implementation Plan

Living document for what `integritee` actually does today, what its
moving parts are, and what work is still outstanding. The single source of
truth for status/ownership is Linear
[CC-171](https://linear.app/cohereai/issue/CC-171/design-automated-ci-flow-build-measure-publish-policy);
this doc captures the design and the in-flight design decisions that have
been made along the way.

## Goal

Produce a **signed, public attestation policy** per release that ties a
specific model container image to the exact set of TDX register values
(MRTD, RTMR0–3) it should produce when running inside our confidential
PodVM. The policy is uploaded to Intel Trust Authority (ITA) so the TNG
gateway can require it at attestation time.

## End-to-end Architecture

```
+--------------------+         +------------------------+
| integritee         |         | cloud-api-adaptor      |
| (this repo)        |         | (cohere branch)        |
+--------------------+         +------------------------+
        |                                  |
        |  podspec.yaml + rules +          |  builds PodVM disk via mkosi
        |  genpolicy-settings              |  publishes OCI artifact to GHCR
        |                                  |  and a compute image to GCP
        v                                  v
+--------------------+         +------------------------+
| attest-model.yaml  | <-----  | GHCR PodVM artifact    |
| (GitHub Actions)   |         |  + disk.tar.gz +       |
|                    |         |  + measurements.json   |
|  - genpolicy       |         +------------------------+
|  - cvm-measure     |
|  - build predicate |         +------------------------+
|  - sign w/ Sigstore| <-----  | Intel Trust Authority  |
|  - upload to ITA   |  policy | (Appraisal policy slot)|
|  - cut GH release  |         +------------------------+
+--------------------+
        |
        v
+-----------------------------------+
| GitHub Release (per version):     |
|   {model}/measurements.json       |
|   {model}/kata-policy.rego        |
|   {model}/predicate.json          |
|   {model}/attestation.sigstore.json|
|   ita-attestation-policy.rego     |
+-----------------------------------+
        |
        v consumed by
+-----------------------------------+
| TNG: looks up latest GH release,  |
| verifies Sigstore bundle, extracts|
| policy_id, requests ITA token     |
+-----------------------------------+
```

## Pipeline steps (`.github/workflows/attest-model.yaml`)

1. **Install tools** — `cvm-measure`, `genpolicy` (Kata static bundle),
   `cosign`, `oras`, `mtools`.
2. **Authenticate to GCP** via Workload Identity Federation (no static
   keys). Service account: `github-ci@cohere-confidential-computing`.
3. **Fetch baseline** for the target machine type from
   [`cohere-ai/cohere-cc-baselines`](https://github.com/cohere-ai/cohere-cc-baselines).
   Requires SSO-authorized `GH_PAT`.
4. **Fetch OVMF firmware** by SHA384 from the public
   `gce_tcb_integrity` Google Cloud Storage bucket.
5. **Pull PodVM artifact** from GHCR via `oras`, then run
   `cvm-measure extract-uki` to produce `BOOTX64.EFI`.
6. **For each model:**
   - merge `rules/rules.rego` + per-model `rules.rego`
   - merge `rules/genpolicy-settings.json` + per-model override
   - run `genpolicy -r` → `kata-policy.rego`
   - run `genpolicy -b` → base64 initdata
   - decode initdata → `initdata.toml`
   - `cvm-measure tdx --firmware OVMF.fd --uki BOOTX64.EFI --baseline …
      --initdata initdata.toml` → `measurements.json` (MRTD + RTMR0–3)
7. **Generate ITA policy** — `scripts/generate-ita-policy.py` reads the
   template (`attestation-policy/template.rego`), static TDX reference
   values (`attestation-policy/tdx-static-ref-vals.yaml`), and per-model
   `measurements.json` files. It replaces the `${TDX_MATCH_BLOCKS}`
   placeholder with one `matches_tdx if { … }` block per model
   (Rego logical-OR) → `ita-attestation-policy.rego`.
8. **Upload policy to ITA** via `scripts/upload-ita-policy.sh`, returning
   a `policy_id`.
9. **Build in-toto predicate** per model.
10. **Sign predicate** with `cosign attest-blob` (keyless Sigstore +
    Rekor entry, chained via `previous_rekor_log_index`).
11. **Cut GitHub Release** with all per-model artifacts attached.

## Moving parts

- **`cohere-ai/cvm-measure`** — Python tooling that computes expected TDX
  register values. Currently pinned to feature branch
  `alhassankhedr/cc-167-tdx-measurement-toolkit` because the CLI / UKI
  extraction modules have not been merged to `main` yet. Marker in
  `attest-model.yaml`:
  ```yaml
  # TODO: remove this branch pin once the cvm-measure CLI/UKI extraction
  #       branch merges to main.
  CVM_MEASURE_REF: "alhassankhedr/cc-167-tdx-measurement-toolkit"
  ```
- **`cohere-ai/cohere-cc-baselines`** — TDX CCEL event-log baselines per
  GCP machine type, e.g. `baselines/gcp/tdx/a3-highgpu-1g.json`. Read via
  GitHub API using `GH_PAT` (must be SAML-authorized for `cohere-ai`).
- **`cohere-ai/cloud-api-adaptor` (`cohere` branch)** — builds the PodVM
  OCI artifact (`podvm:cohere-latest-ubuntu-{release,debug}`) and (today)
  also creates a GCP Compute Engine image in `cohere-artifacts`. This
  repo *only* reads the PodVM from GHCR right now; future direction is
  to read the disk from a GCS bucket in `cohere-artifacts` instead.
- **`gce_tcb_integrity` GCS bucket** (Google-managed, public) — source
  of OVMF firmware binaries indexed by SHA384.
- **Intel Trust Authority** — hosts the appraisal policy; consumed by
  TNG when attesting a workload.
- **Sigstore / Rekor** — public transparency log for the attestation
  signature; bundle is included in the GitHub release.
- **Kata Containers releases** — provide the `genpolicy` binary
  (pinned to `KATA_VERSION=3.12.0`); fetched at run time by
  `scripts/fetch-genpolicy.sh`.

## ITA policy strategy

ITA enforces `max_policy = 5` for our tenant. To avoid hitting that
ceiling on every release we use a **blue/green** model: two pre-created
policy slots, alternated on each release. Consumers (TNG) reference the
slot by `policy_id`, so cutover is a switch of which `policy_id` is
served.

| Slot | Name | `policy_id` |
|---|---|---|
| A | `integritee-policy-a` | `cbeedffa-e224-4664-b6b4-573fcd4133d3` |
| B | `integritee-policy-b` | `ecdf9171-2f85-47b4-9941-703118f731a8` |

Both currently host the canonical `tdx_h100_pp_image` policy content plus
one slot-tag rule (`integritee_slot_{a,b} := true`) so ITA's
content-dedup hash treats them as distinct. They will be overwritten
in alternation when the workflow starts publishing real measurements.

### ITA upload notes

- The `policy` JSON field must be **plain rego source text**, not
  base64-encoded.
- For `attestation_type: "Composite Attestation"`, the request body
  must **omit `policy_type`** entirely.
- ITA dedups uploads by **semantic content hash** (comments stripped).
  Two policies with identical semantics but different comments will
  collide. To differentiate the two blue/green slots we inject a
  unique no-op rule per slot.

## Identity & permissions

GitHub Actions in this repo uses GCP Workload Identity Federation, no
static service-account keys.

- **WIF pool / provider**: `github-ci-pool` / `github-provider` in
  `cohere-confidential-computing`. Attribute condition restricts the
  pool to `cohere-ai/integritee` and `cohere-ai/cloud-api-adaptor`.
- **Service account this repo impersonates**: `github-ci@cohere-confidential-computing.iam.gserviceaccount.com`
- **Repo secrets**:
  - `GCP_WORKLOAD_IDENTITY_PROVIDER` — full provider resource name
  - `GCP_SERVICE_ACCOUNT` — SA email above
  - `GH_PAT` — SAML-SSO-authorized PAT for reading
    `cohere-ai/cohere-cc-baselines`
  - `ITA_API_URL` / `ITA_ADMIN_API_KEY` — ITA tenant credentials for
    `Upload policy to ITA` step
- **Token used for in-repo operations** (GHCR pull, releases) is the
  workflow's own `${{ github.token }}` plus `packages: read` permission.

### Target IAM (pending follow-up infra PR)

Bràné asked us to tighten `github-ci` to exactly what it needs:

- `roles/storage.objectViewer` bucket-scoped on the future
  `gs://cohere-artifacts-podvm` bucket — read PodVM disk from GCS
  instead of (or in addition to) GHCR.
- `roles/artifactregistry.reader` repo-scoped on
  `projects/cohere-confidential-computing/locations/us/repositories/fortress`
  — pull the model container image referenced by the podspecs
  (`us-docker.pkg.dev/cohere-confidential-computing/fortress/vllm-server`).
- Drop the existing project-wide `roles/artifactregistry.reader` grants
  on `github-ci` in both `cohere-confidential-computing` and
  `cohere-artifacts`.

## PodVM source dependency

Today the workflow `oras pull`s the PodVM artifact directly from GHCR:
```
ghcr.io/cohere-ai/cloud-api-adaptor/podvm:{cohere-latest-ubuntu-debug,
                                           cohere-latest-ubuntu-release,
                                           podvm-vN-N-N-ubuntu-{release,debug}}
```
The disk is then extracted on the runner and fed to `cvm-measure
extract-uki`.

The forward plan is for `cloud-api-adaptor`'s deploy job to publish the
PodVM disk into `gs://cohere-artifacts-podvm` alongside its compute
image, and for this workflow to read the disk from GCS instead. That
makes `cohere-artifacts` the single source of truth for both the OS
image and the model container images.

### Coordinating PodVM driver bumps

The PodVM ships with NVIDIA drivers. Any time the driver version changes
(e.g. `cloud-api-adaptor` PR #28: `580.126.20 → 580.159.03`), the
expected `x-nvidia-gpu-driver-version` value baked into the ITA policy
must change too. The blue/green slot strategy lets us:

1. Stage the new driver version's policy in the **inactive** slot.
2. Validate end-to-end with TNG against that slot.
3. Cut over consumers to that slot.
4. Treat the previous slot as the rollback target.

## Open work / TODOs

In rough order of dependency:

- [ ] Merge `cohere-ai/cvm-measure` `cc-167` branch to `main`, then drop
      the `CVM_MEASURE_REF` pin in `attest-model.yaml` (the comment in
      the workflow flags this).
- [ ] Stand up `gs://cohere-artifacts-podvm` in the infra repo and have
      `cloud-api-adaptor`'s `deploy-gcp-cohere.yaml` write the PodVM
      disk there. Then point this workflow at GCS instead of GHCR.
- [ ] Land the IAM tightening PR for `github-ci` (bucket-scoped
      `objectViewer` + repo-scoped `artifactregistry.reader`) and drop
      the project-wide AR reader grants.
- [ ] Coordinate the NVIDIA driver bump (`cloud-api-adaptor` PR #28)
      with an ITA policy refresh in the inactive blue/green slot.

## References

- Linear: [CC-171 — Design automated CI flow: build → measure → publish policy](https://linear.app/cohereai/issue/CC-171/design-automated-ci-flow-build-measure-publish-policy)
- Infra IAM (merged): [`cohere-ai/infra#15428`](https://github.com/cohere-ai/infra/pull/15428)
- Infra IAM apply-permission fix (merged): [`cohere-ai/infra#15437`](https://github.com/cohere-ai/infra/pull/15437)
- PodVM NVIDIA driver bump (open): [`cohere-ai/cloud-api-adaptor#28`](https://github.com/cohere-ai/cloud-api-adaptor/pull/28)
