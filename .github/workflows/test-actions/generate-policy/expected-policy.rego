# ITA TDX+NVGPU appraisal policy.
#
# Each matches_tdx block checks a specific (MRTD, RTMR0-3) combination.
# The policy matches if ANY block matches (logical OR across models).

import rego.v1

default match := false

match if {
    matches_tdx
    matches_nvgpu
}


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

# Target 0: cmp-l
matches_tdx if {
    tdx_base_checks
    tdx := input.tdx

    tdx.tdx_mrtd == "feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162"
    tdx.tdx_rtmr0 == "1da1ab59b71241ac9d4c758a2cf25df1c7f9e32c5e4995d1ded8f0f03abd33087d98676517d228e2bd02fc9ca9c280d5"
    tdx.tdx_rtmr1 == "1b511a8dd1c31d83e5e0ee9f2391209ce9939410c7fa9d979e66b8fc39a58a45b56b22e4751050873726769cb5e55074"
    tdx.tdx_rtmr2 == "3c0fc32a340dbead212e32c50aa5a28936ceda1a5481767607a5291a67790de894fab2f3948b3294a369727c8f8d09a6"
    tdx.tdx_rtmr3 == "71f92a6b66fef04f4ee529373cf778eae133e3474fcac1c3fef261eda6f13d0a15089c843398beab51bd660321a69389"
}

nvgpu_base_checks if {
    nvgpu := input.nvgpu

    nvgpu.secboot == true
    nvgpu.hwmodel == "GH100"
    nvgpu["x-nvidia-gpu-manufacturer"] == "NVIDIA Corporation"
    nvgpu["x-nvidia-gpu-driver-version"] == "580.159.04"
    nvgpu["x-nvidia-gpu-vbios-version"] == "96.00.CF.00.01"
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-nonce-match"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-arch-check"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-attestation-report-cert-chain-validated"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-attestation-report-parsed"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-attestation-report-signature-verified"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-driver-rim-cert-validated"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-driver-rim-driver-measurements-available"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-driver-rim-schema-fetched"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-driver-rim-schema-validated"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-driver-rim-signature-verified"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-vbios-rim-cert-validated"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-vbios-rim-measurements-available"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-vbios-rim-schema-fetched"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-vbios-rim-schema-validated"] == true
    nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-vbios-rim-signature-verified"] == true
}

matches_nvgpu if {
    nvgpu_base_checks
    input.nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-measurements-match"] == true
}

# Workaround for issue on GCP machines: https://github.com/NVIDIA/nvtrust/issues/132
matches_nvgpu if {
    nvgpu_base_checks
    input.nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-gpu-measurements-match"] == false
    input.nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-mismatch-indexes"] == [9]
    record := input.nvgpu["x-nvidia-attestation-detailed-result"]["x-nvidia-mismatch-measurement-records"][0]
    record.index == 9
    record.runtimeValue == "c80a9b62ce0d41184bb1ad0f6334d9400a2d2514ef92003b1c043410f91b7309144325a3e01c58b8bd6e198f5dda3b9b"
}
