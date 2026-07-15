# ITA TDX+NVGPU appraisal policy.
#
# Each matches_tdx block checks a specific baseline measurement combination.
# The policy matches if ANY block matches.

import rego.v1

default match := false

match if {
    matches_tdx
    matches_nvgpu
}

${POLICY_NONCE}

# TDX TCB is acceptable if up-to-date OR if out-of-date but within the TTL grace period
# Based on: https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-platform-tcb.html#tcb-ttl-policy

tcb_level_is_up2date if {
    # Up-to-date TCB status values
    tcb_level_up2date := {"UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded"}
    tcb_level_up2date[input.tdx.attester_tcb_status]
}

tcb_level_outofdate_within_ttl if {
    tcb_level_outofdate := {"OutOfDate", "OutOfDateConfigurationNeeded"}
    tcb_level_outofdate[input.tdx.attester_tcb_status]
    attester_tcb_date_ns := time.parse_rfc3339_ns(input.tdx.attester_tcb_date)
    ttl_period := 6 # months
    expiry_date_ns := time.add_date(attester_tcb_date_ns, 0, ttl_period, 0)
    expiry_date_ns > time.now_ns()
}

tcb_level_acceptable if { tcb_level_is_up2date }
tcb_level_acceptable if { tcb_level_outofdate_within_ttl }

tdx_base_checks if {
    tcb_level_acceptable

    tdx := input.tdx
    tdx.tdx_mrsignerseam == "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    tdx.tdx_mrconfigid == "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    tdx.tdx_mrowner == "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    tdx.tdx_mrownerconfig == "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    tdx.tdx_seam_attributes == "0000000000000000"
    tdx.tdx_td_attributes == "0000001000000000"
    tdx.tdx_is_debuggable == false
    tdx.tdx_seamsvn >= 271
}

${TDX_MATCH_BLOCKS}

# NRAS V3 token format: GPU claims are nested under input.nvgpu.claim_details
# with per-device keys (e.g. "GPU-0"). The top-level x-nvidia-overall-att-result
# summarises the result across all GPUs.
# See: https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html

nvgpu_device_base_checks(gpu) if {
    gpu.hwmodel == "GH100"
    gpu["x-nvidia-gpu-driver-version"] == "${NVIDIA_DRIVER_VERSION}"

    gpu["x-nvidia-gpu-attestation-report-nonce-match"] == true
    gpu["x-nvidia-gpu-arch-check"] == true
    gpu["x-nvidia-gpu-attestation-report-parsed"] == true
    gpu["x-nvidia-gpu-attestation-report-signature-verified"] == true
    gpu["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-status"] == "valid"
    gpu["x-nvidia-gpu-attestation-report-cert-chain-fwid-match"] == true

    gpu["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-status"] == "valid"
    gpu["x-nvidia-gpu-driver-rim-fetched"] == true
    gpu["x-nvidia-gpu-driver-rim-measurements-available"] == true
    gpu["x-nvidia-gpu-driver-rim-schema-validated"] == true
    gpu["x-nvidia-gpu-driver-rim-signature-verified"] == true
    gpu["x-nvidia-gpu-driver-rim-version-match"] == true

    gpu["x-nvidia-gpu-vbios-rim-cert-chain"]["x-nvidia-cert-status"] == "valid"
    gpu["x-nvidia-gpu-vbios-rim-fetched"] == true
    gpu["x-nvidia-gpu-vbios-rim-measurements-available"] == true
    gpu["x-nvidia-gpu-vbios-rim-schema-validated"] == true
    gpu["x-nvidia-gpu-vbios-rim-signature-verified"] == true
    gpu["x-nvidia-gpu-vbios-rim-version-match"] == true
}

nvgpu_base_checks if {
    input.nvgpu["x-nvidia-overall-att-result"] == true
    count(input.nvgpu.claim_details) > 0

    every gpu_key in object.keys(input.nvgpu.claim_details) {
        gpu := input.nvgpu.claim_details[gpu_key]
        gpu.secboot == true
        nvgpu_device_base_checks(gpu)
    }
}

matches_nvgpu if {
    nvgpu_base_checks
    every gpu_key in object.keys(input.nvgpu.claim_details) {
        input.nvgpu.claim_details[gpu_key].measres == "success"
    }
}

# Narrow workaround for the deterministic GCP firmware mismatch:
# https://github.com/NVIDIA/nvtrust/issues/132
matches_nvgpu if {
    input.nvgpu["x-nvidia-overall-att-result"] == false
    count(input.nvgpu.claim_details) == 1

    some gpu_key in object.keys(input.nvgpu.claim_details)
    gpu := input.nvgpu.claim_details[gpu_key]
    nvgpu_device_base_checks(gpu)
    gpu.secboot == true
    {"fail", "comparison-fail"}[gpu.measres]

    records := gpu["x-nvidia-mismatch-measurement-records"]
    count(records) == 1
    record := records[0]
    record.index == 9
    record.measurementSource == "Firmware"
    record.goldenSize == 48
    record.goldenValue == "4b3ed0f834d10fef95e61615edc5b4e98ec78cff39323993b3218f0cd62507978cf64e4487520bc7e560fde71ea0fc75"
    record.runtimeSize == 48
    record.runtimeValue == "c80a9b62ce0d41184bb1ad0f6334d9400a2d2514ef92003b1c043410f91b7309144325a3e01c58b8bd6e198f5dda3b9b"
}
