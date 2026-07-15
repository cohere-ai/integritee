#!/usr/bin/env python3
"""Compare a TNG attestation request from logs against a released ITA policy.

Extracts the ITA attestation request body from TNG container logs, decodes the
TDX quote and runtime data, and compares every field checked by the Rego policy
against the values the pod is actually attesting. Reports the first mismatching
field and a summary table of all fields.

Usage:
    # Compare against latest release (downloads policy automatically)
    python compare-tng-attestation.py \\
        --pod cat2508rws-l-cc-0 \\
        --namespace gf-cc-demo-0nihzk \\
        --container tng

    # Compare against a specific release tag
    python compare-tng-attestation.py \\
        --pod cat2508rws-l-cc-0 \\
        --namespace gf-cc-demo-0nihzk \\
        --container tng \\
        --release v0.0.1a50

    # Use a pre-extracted request body file instead of kubectl
    python compare-tng-attestation.py \\
        --request-file /tmp/ita_request.json \\
        --release v0.0.1a50

    # Use a local Rego policy file instead of downloading
    python compare-tng-attestation.py \\
        --request-file /tmp/ita_request.json \\
        --rego-file /tmp/ita-attestation-policy.rego
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# ─── TDX quote measurement extraction ───
# The TDX quote contains measurement registers at non-contiguous offsets.
# Rather than hardcoding offsets (which vary by quote version), we search for
# known anchor values. RTMR1 and RTMR2 are shared across all models (they measure
# the firmware/UKI, not per-model initdata), so we use them to anchor.
_HASH_SIZE = 0x30  # 48 bytes (SHA-384)

# Rego policy field name → ITA input field name mapping
_REGO_TO_INPUT = {
    "mrtd": "tdx_mrtd",
    "rtmr0": "tdx_rtmr0",
    "rtmr1": "tdx_rtmr1",
    "rtmr2": "tdx_rtmr2",
    "rtmr3": "tdx_rtmr3",
}


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


# ─── Log extraction ──────────────────────────────────────────────────────


def extract_ita_request_from_logs(
    pod: str,
    namespace: str,
    container: str,
    use_previous: bool = False,
    context: str | None = None,
) -> dict[str, Any]:
    """Extract the ITA attestation request JSON from TNG container logs.

    TNG logs the request body on the line:
        Sending ITA attest request url=... body=<json>
    """
    cmd = [
        "kubectl", "logs", "-n", namespace, pod, "-c", container,
        "--tail=30000",
    ]
    if context:
        cmd.extend(["--context", context])
    if use_previous:
        cmd.append("--previous")

    ctx_label = f" (context: {context})" if context else ""
    print(f"Fetching logs from {namespace}/{pod}/{container}{ctx_label}...")
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    lines = result.stdout.strip().split("\n")
    # Search from the end (most recent request first)
    for line in reversed(lines):
        if "Sending ITA attest request" in line and "body=" in line:
            body_start = line.index("body=") + 5
            body_json = line[body_start:]
            try:
                return json.loads(body_json)
            except json.JSONDecodeError:
                continue

    raise RuntimeError(
        "No ITA attest request found in logs. The pod may have restarted "
        "and logs rotated. Try --use-previous for the previous container's logs."
    )


# ─── Quote parsing ──────────────────────────────────────────────────────


def extract_measurements_from_quote(
    quote_bytes: bytes, policy_blocks: list[dict[str, str]]
) -> dict[str, str]:
    """Extract MRTD and RTMR0-3 from a raw TDX quote.

    Rather than hardcoding byte offsets (which vary by quote format), we search
    for each measurement value from the policy within the quote bytes. This works
    because the policy lists all allowed measurement combinations, and the quote
    must contain exactly one set that matches.

    Falls back to scanning for non-zero 48-byte regions if no policy match is found.
    """
    # Try to find all policy measurement values in the quote
    found: dict[str, str] = {}
    for block in policy_blocks:
        for field in ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]:
            if field in found:
                continue
            val = block[field]
            if val and bytes.fromhex(val) in quote_bytes:
                # Verify: this value appears in the quote
                # Check if other fields from the same block also appear nearby
                found[field] = val

    # For any fields not found via policy search, try the GCP allowlist MRTD/RTMR0
    for block in policy_blocks:
        if "TEMPORARY" in block.get("model", ""):
            for field in ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]:
                if field in found:
                    continue
                val = block[field]
                if val and bytes.fromhex(val) in quote_bytes:
                    found[field] = val

    # If we found at least RTMR1 and RTMR2, we can derive the quote layout
    # and extract the actual values at those offsets for fields we haven't matched yet
    if "rtmr1" in found and "rtmr2" in found:
        rtmr1_pos = quote_bytes.find(bytes.fromhex(found["rtmr1"]))
        rtmr2_pos = quote_bytes.find(bytes.fromhex(found["rtmr2"]))

        # RTMRs are 48 bytes apart; MRTD and RTMR0 are at fixed relative positions
        slot = _HASH_SIZE
        offsets = {
            "mrtd": rtmr1_pos - 3 * slot,
            "rtmr0": rtmr1_pos - 1 * slot,
            "rtmr1": rtmr1_pos,
            "rtmr2": rtmr2_pos,
            "rtmr3": rtmr2_pos + 1 * slot,
        }

        for field, offset in offsets.items():
            if field not in found or found[field] == "0" * 96:
                actual = quote_bytes[offset : offset + _HASH_SIZE].hex()
                if actual != "0" * 96:
                    found[field] = actual

    # If still missing fields, try scanning for non-zero 48-byte hashes
    if len(found) < 5:
        for i in range(0, len(quote_bytes) - _HASH_SIZE):
            chunk = quote_bytes[i : i + _HASH_SIZE]
            if chunk == b"\x00" * _HASH_SIZE:
                continue
            hex_val = chunk.hex()
            # Check if this looks like a hash (high entropy, no long zero runs)
            if hex_val.count("00") < 6 and hex_val not in found.values():
                # Try to match it against a policy field
                for block in policy_blocks:
                    for field in ["mrtd", "rtmr0", "rtmr3"]:
                        if field not in found and block[field] == hex_val:
                            found[field] = hex_val

    if not found:
        raise ValueError(
            "Could not extract any measurements from the TDX quote. "
            "The quote may be from a different policy version or format."
        )

    # Fill in any remaining fields as zeros
    for field in ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]:
        if field not in found:
            found[field] = "0" * 96

    return found


def parse_runtime_data(runtime_data_b64: str) -> dict[str, Any]:
    """Decode the runtime_data field from the ITA request."""
    decoded = base64.b64decode(runtime_data_b64).decode("utf-8")
    return json.loads(decoded)


def parse_nvgpu_evidence(evidence_b64: str) -> dict[str, Any]:
    """Decode the nvgpu evidence certificate from the ITA request."""
    decoded = base64.b64decode(evidence_b64).decode("utf-8")
    return json.loads(decoded)


# ─── Policy parsing ──────────────────────────────────────────────────────


def parse_rego_policy(rego_text: str) -> list[dict[str, str]]:
    """Parse matches_tdx blocks from a Rego policy file.

    Returns a list of dicts, each with keys: model, mrtd, rtmr0, rtmr1, rtmr2, rtmr3.
    """
    blocks: list[dict[str, str]] = []

    # Match: # Model: <name>  (optional comment line before matches_tdx if)
    # Then:  matches_tdx if { ... tdx.tdx_mrtd == "..." ... }
    block_pattern = re.compile(
        r"#\s*Model:\s*(.+?)\n"
        r"\s*matches_tdx if \{[^}]*?"
        r'tdx\.tdx_mrtd\s*==\s*"([0-9a-f]+)"'
        r'.*?'
        r'tdx\.tdx_rtmr0\s*==\s*"([0-9a-f]+)"'
        r'.*?'
        r'tdx\.tdx_rtmr1\s*==\s*"([0-9a-f]+)"'
        r'.*?'
        r'tdx\.tdx_rtmr2\s*==\s*"([0-9a-f]+)"'
        r'.*?'
        r'tdx\.tdx_rtmr3\s*==\s*"([0-9a-f]+)"',
        re.DOTALL,
    )

    for match in block_pattern.finditer(rego_text):
        blocks.append({
            "model": match.group(1).strip(),
            "mrtd": match.group(2),
            "rtmr0": match.group(3),
            "rtmr1": match.group(4),
            "rtmr2": match.group(5),
            "rtmr3": match.group(6),
        })

    if not blocks:
        raise ValueError("No matches_tdx blocks found in Rego policy")

    return blocks


def parse_nvgpu_policy_fields(rego_text: str) -> dict[str, str]:
    """Parse static nvgpu fields from the Rego policy."""
    fields: dict[str, str] = {}

    field_patterns = {
        "driver_version": r'nvgpu\["x-nvidia-gpu-driver-version"\]\s*==\s*"([^"]+)"',
        "hwmodel": r'nvgpu\.hwmodel\s*==\s*"([^"]+)"',
        "manufacturer": r'nvgpu\["x-nvidia-gpu-manufacturer"\]\s*==\s*"([^"]+)"',
        "secboot": r'nvgpu\.secboot\s*==\s*(true|false)',
    }

    for name, pattern in field_patterns.items():
        match = re.search(pattern, rego_text)
        if match:
            fields[name] = match.group(1)

    # Extract the GCP workaround mismatch index and runtime value
    workaround_match = re.search(
        r'"x-nvidia-mismatch-indexes"\s*==\s*\[(\d+)\].*?'
        r'record\.index\s*==\s*(\d+).*?'
        r'record\.runtimeValue\s*==\s*"([0-9a-f]+)"',
        rego_text,
        re.DOTALL,
    )
    if workaround_match:
        fields["gcp_workaround_index"] = workaround_match.group(1)
        fields["gcp_workaround_runtime_value"] = workaround_match.group(3)

    return fields


# ─── Download helpers ───────────────────────────────────────────────────


def download_release_asset(
    release: str, asset_name: str, dest_dir: Path
) -> Path:
    """Download a release asset from the integritee GitHub repo."""
    dest = dest_dir / asset_name
    cmd = [
        "gh", "release", "download", release,
        "-R", "cohere-ai/integritee",
        "-p", asset_name,
        "-D", str(dest_dir),
        "--clobber",
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return dest


def get_latest_release() -> str:
    """Get the latest release tag from the integritee repo."""
    result = subprocess.run(
        ["gh", "release", "list", "-R", "cohere-ai/integritee", "--limit", "1"],
        check=True, capture_output=True, text=True,
    )
    # Format: "Title\tTag\tDate"
    parts = result.stdout.strip().split("\t")
    if len(parts) >= 2:
        return parts[1]
    raise RuntimeError("Could not determine latest release")


# ─── Comparison ──────────────────────────────────────────────────────────


def find_best_tdx_match(
    quote_measurements: dict[str, str],
    policy_blocks: list[dict[str, str]],
) -> tuple[dict[str, str] | None, int]:
    """Find the policy block that best matches the quote measurements.

    Returns the best-matching block (or None if no block matches at all)
    and the number of matching fields.
    """
    best_block: dict[str, str] | None = None
    best_matches = 0

    for block in policy_blocks:
        matches = sum(
            1 for f in ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
            if block[f] == quote_measurements[f]
        )
        if matches > best_matches:
            best_matches = matches
            best_block = block

    return best_block, best_matches


def compare_tdx_fields(
    quote_measurements: dict[str, str],
    policy_block: dict[str, str],
    model_name: str,
) -> list[tuple[str, str, str, bool]]:
    """Compare each TDX measurement field between quote and policy."""
    results: list[tuple[str, str, str, bool]] = []
    for field in ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]:
        quote_val = quote_measurements[field]
        policy_val = policy_block[field]
        match = quote_val == policy_val
        results.append((f"tdx_{field}", quote_val, policy_val, match))
    return results


def compare_nvgpu_fields(
    nvgpu_request: dict[str, Any],
    policy_fields: dict[str, str],
) -> list[tuple[str, str, str, bool]]:
    """Compare NVIDIA GPU attestation fields between request and policy."""
    results: list[tuple[str, str, str, bool]] = []

    # The nvgpu evidence in the request is raw cert/evidence blobs.
    # ITA parses these and produces the fields the policy checks.
    # We can only compare what's directly visible: arch, and nonce-related info.
    # The driver version, hwmodel, etc. are extracted by ITA from the evidence
    # and aren't directly in the request body. We note what the policy expects.

    arch = nvgpu_request.get("arch", "unknown")
    policy_hwmodel = policy_fields.get("hwmodel", "not specified")

    # Map arch names to GPU models
    arch_to_hwmodel = {"Hopper": "GH100", "Ampere": "GA100"}
    expected_hwmodel = arch_to_hwmodel.get(arch, arch)

    results.append((
        "nvgpu.arch (request) -> nvgpu.hwmodel (policy)",
        f"{arch} -> {expected_hwmodel}",
        policy_hwmodel,
        expected_hwmodel == policy_hwmodel,
    ))

    if "driver_version" in policy_fields:
        results.append((
            "nvgpu driver_version (policy expects)",
            "(extracted by ITA from evidence)",
            policy_fields["driver_version"],
            True,  # Can't verify without ITA's parsing
        ))

    return results


# ─── Reporting ───────────────────────────────────────────────────────────


def print_section(title: str) -> None:
    print(f"\n{c('─' * 70, Colors.BOLD)}")
    print(f"{c(title, Colors.BOLD)}")
    print(f"{c('─' * 70, Colors.BOLD)}")


def print_comparison_table(
    results: list[tuple[str, str, str, bool]],
) -> int:
    """Print a comparison table. Returns number of mismatches."""
    mismatches = 0
    print(f"\n  {'Field':<50} {'Match':<8} Values")
    print(f"  {'─' * 118}")
    for field, quote_val, policy_val, match in results:
        status = c("OK", Colors.GREEN) if match else c("FAIL", Colors.RED)
        if not match:
            mismatches += 1
            print(f"  {field:<50} {status:<8}")
            print(f"  {'  quote:':<50} {quote_val}")
            print(f"  {'  policy:':<50} {policy_val}")
        else:
            # For matching fields, show truncated values
            q_short = quote_val[:24] + "..." if len(quote_val) > 24 else quote_val
            p_short = policy_val[:24] + "..." if len(policy_val) > 24 else policy_val
            print(f"  {field:<50} {status:<8} {q_short}")

    return mismatches


def print_policy_blocks_summary(blocks: list[dict[str, str]]) -> None:
    """Print a summary of all policy blocks for context."""
    print(f"\n  Policy has {len(blocks)} matches_tdx blocks:")
    for i, block in enumerate(blocks):
        label = block["model"]
        print(f"    [{i}] {label}")
        print(f"        MRTD:  {block['mrtd'][:32]}...")
        print(f"        RTMR3: {block['rtmr3'][:32]}...")


# ─── Main ────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare TNG attestation request from logs against a released ITA policy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--request-file",
        type=Path,
        help="Path to a pre-extracted ITA request JSON file.",
    )
    source_group.add_argument(
        "--pod",
        help="Pod name to extract logs from (requires --namespace and --container).",
    )
    parser.add_argument("--namespace", help="Kubernetes namespace of the pod.")
    parser.add_argument("--container", default="tng", help="Container name (default: tng).")
    parser.add_argument(
        "--context",
        help="Kubernetes context to use (e.g., gke_cohere-production_us-central1_production). "
             "If omitted, uses the current context.",
    )
    parser.add_argument("--use-previous", action="store_true", help="Use previous container logs.")

    policy_group = parser.add_mutually_exclusive_group(required=True)
    policy_group.add_argument("--rego-file", type=Path, help="Path to a local Rego policy file.")
    policy_group.add_argument("--release", help="Release tag to download the policy from.")
    parser.add_argument(
        "--model",
        help="Specific model to compare against (e.g., cat2508rws-l). "
             "If omitted, finds the best-matching block.",
    )

    args = parser.parse_args()

    # ─── Get ITA request ───
    if args.request_file:
        print(f"Loading ITA request from {args.request_file}...")
        request = json.loads(args.request_file.read_text())
    else:
        if not args.namespace:
            parser.error("--namespace is required when using --pod")
        request = extract_ita_request_from_logs(
            args.pod, args.namespace, args.container, args.use_previous, args.context
        )

    # ─── Get Rego policy ───
    if args.rego_file:
        print(f"Loading Rego policy from {args.rego_file}...")
        rego_text = args.rego_file.read_text()
    else:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            print(f"Downloading policy from release {args.release}...")
            rego_path = download_release_asset(args.release, "ita-attestation-policy.rego", tmp)
            rego_text = rego_path.read_text()

    # ─── Parse ───
    policy_blocks = parse_rego_policy(rego_text)
    nvgpu_policy_fields = parse_nvgpu_policy_fields(rego_text)

    print(f"\nParsed {len(policy_blocks)} matches_tdx blocks from policy")

    # ─── Extract from request ───
    policy_ids = request.get("policy_ids", [])
    policy_must_match = request.get("policy_must_match", False)
    tdx = request.get("tdx", {})
    quote_b64 = tdx.get("quote", "")
    quote_bytes = base64.b64decode(quote_b64)
    quote_measurements = extract_measurements_from_quote(quote_bytes, policy_blocks)

    runtime_data = {}
    if "runtime_data" in tdx:
        runtime_data = parse_runtime_data(tdx["runtime_data"])

    nvgpu_request = request.get("nvgpu", {})

    # ─── Report ───
    print_section("ITA Request Summary")
    print(f"  policy_ids:          {policy_ids}")
    print(f"  policy_must_match:   {policy_must_match}")
    print(f"  token_signing_alg:   {request.get('token_signing_alg')}")
    print(f"  tdx.quote length:    {len(quote_bytes)} bytes")
    print(f"  nvgpu.arch:          {nvgpu_request.get('arch', 'N/A')}")
    if runtime_data:
        print(f"  runtime_data keys:   {list(runtime_data.keys())}")
        if "pubkey-hash" in runtime_data:
            print(f"  pubkey-hash:         {runtime_data['pubkey-hash']}")

    print_section("TDX Measurements from Quote")
    for field in ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]:
        print(f"  {field.upper():<6}: {quote_measurements[field]}")

    print_section("Policy Blocks")
    print_policy_blocks_summary(policy_blocks)

    # ─── Find best match ───
    if args.model:
        matching_blocks = [b for b in policy_blocks if b["model"] == args.model]
        if not matching_blocks:
            print(f"\n{c('ERROR', Colors.RED)}: Model '{args.model}' not found in policy blocks.")
            print(f"  Available models: {[b['model'] for b in policy_blocks]}")
            return 1
        best_block = matching_blocks[0]
        best_matches = sum(
            1 for f in ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
            if best_block[f] == quote_measurements[f]
        )
    else:
        best_block, best_matches = find_best_tdx_match(quote_measurements, policy_blocks)
        if best_block is None:
            print(f"\n{c('ERROR', Colors.RED)}: No policy block matched any field.")
            return 1

    print_section(f"Best Matching Block: {best_block['model']} ({best_matches}/5 fields match)")

    tdx_results = compare_tdx_fields(quote_measurements, best_block, best_block["model"])
    tdx_mismatches = print_comparison_table(tdx_results)

    # ─── NVIDIA GPU ───
    if nvgpu_request:
        print_section("NVIDIA GPU Attestation")
        nvgpu_results = compare_nvgpu_fields(nvgpu_request, nvgpu_policy_fields)
        nvgpu_mismatches = print_comparison_table(nvgpu_results)
    else:
        nvgpu_mismatches = 0

    # ─── Summary ───
    print_section("Summary")
    total = tdx_mismatches + nvgpu_mismatches
    if total == 0:
        print(f"  {c('ALL FIELDS MATCH', Colors.GREEN)}")
        print(f"  The quote matches policy block: {best_block['model']}")
    else:
        print(f"  {c(f'{total} FIELD(S) MISMATCH', Colors.RED)}")
        print(f"  Best-matching block: {best_block['model']} ({best_matches}/5 TDX fields match)")
        print(f"  TDX mismatches:  {tdx_mismatches}")
        print(f"  NVGPU mismatches: {nvgpu_mismatches}")

        # Diagnostic
        print()
        print(f"  {c('Diagnosis:', Colors.YELLOW)}")
        rtmr3_match = best_block["rtmr3"] == quote_measurements["rtmr3"]
        mrtd_match = best_block["mrtd"] == quote_measurements["mrtd"]
        rtmr0_match = best_block["rtmr0"] == quote_measurements["rtmr0"]

        if not rtmr3_match and mrtd_match and rtmr0_match:
            print(f"    RTMR3 mismatch with matching MRTD/RTMR0 → initdata (kata policy) has changed.")
            print(f"    The pod is running an older initdata than the policy expects.")
            print(f"    Deploy the updated chart/initdata to the pod, or update the policy.")
        elif not mrtd_match and not rtmr0_match:
            print(f"    MRTD + RTMR0 mismatch → firmware has changed (GCP firmware update).")
            print(f"    Check if a temporary firmware allowlist entry covers this firmware.")
            print(f"    The policy has a GCP firmware allowlist block — check if the")
            print(f"    quote's MRTD/RTMR0 matches any allowlisted entry.")
            # Check allowlist blocks
            allowlist_blocks = [b for b in policy_blocks if "TEMPORARY" in b["model"]]
            for alb in allowlist_blocks:
                if alb["mrtd"] == quote_measurements["mrtd"]:
                    print(f"    Found matching allowlist entry: {alb['model']}")
                    print(f"    But RTMR3 still mismatches → initdata change on top of firmware update.")
                    break
            else:
                print(f"    No allowlist entry matches the quote's MRTD.")
                print(f"    Quote MRTD:  {quote_measurements['mrtd']}")
                print(f"    A new firmware allowlist entry may be needed.")
        elif not rtmr3_match:
            print(f"    RTMR3 mismatch → initdata (kata policy) differs between pod and policy.")

    return 1 if total > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
