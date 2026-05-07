# Base ITA TDX appraisal policy template.
#
# The workflow injects per-model measurement blocks into this template
# to produce the final attestation policy uploaded to ITA.
#
# Each measurement block checks a specific (MRTD, RTMR0-3) combination.
# The policy matches if ANY block matches (logical OR across models).

import rego.v1

default match := false

# __MEASUREMENT_BLOCKS__ will be replaced by the generate-ita-policy.py script
# with one `match if { ... }` block per model.
