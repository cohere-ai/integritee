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

${POLICY_NONCE}

${TDX_MATCH_BLOCKS}

nvgpu_base_checks if {
    nvgpu := input.nvgpu

    nvgpu.secboot == true
    nvgpu.hwmodel == "GH100"
    nvgpu["x-nvidia-gpu-manufacturer"] == "NVIDIA Corporation"
    nvgpu["x-nvidia-gpu-driver-version"] == "580.126.20"
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
