#!/usr/bin/env python3
"""Build in-toto attestation predicates for each model.

Reads per-model artifacts (measurements, policy info) and per-model CVM
metadata (meta.json) to produce a predicate JSON conforming to the custom
attestation-policy-ledger/v1 type.

Usage:
    python build-predicate.py \
        --artifacts-dir artifacts/ \
        --cvm-artifacts-dir cvm-artifacts/ \
        --policy-id <uuid> \
        --version v0.0.1 \
        --genpolicy-version 3.12.0 \
        --cvm-measure-version 0.3.0 \
        --previous-log-index 0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PREDICATE_TYPE = "https://cohere.com/attestation-policy-ledger/v1"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_predicate(
    model: str,
    measurements: dict,
    policy_id: str,
    rego_policy: str,
    initdata_hash: str,
    previous_rekor_log_index: int,
    release_version: str,
    genpolicy_version: str,
    cvm_measure_version: str,
    firmware_ref: str,
    uki_ref: str,
    baseline_ref: str,
) -> dict:
    return {
        "model_path": model,
        "event_type": "policy_activated",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "release_version": release_version,
        "measurements": measurements,
        "policy_id": policy_id,
        "rego_policy_hash": hashlib.sha256(rego_policy.encode()).hexdigest(),
        "initdata_hash": initdata_hash,
        "previous_rekor_log_index": previous_rekor_log_index,
        "tool_versions": {
            "genpolicy": genpolicy_version,
            "cvm_measure": cvm_measure_version,
        },
        "source_artifacts": {
            "firmware_ref": firmware_ref,
            "uki_ref": uki_ref,
            "baseline_ref": baseline_ref,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build in-toto predicates")
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--cvm-artifacts-dir", required=True,
                        help="Directory containing per-model meta.json files")
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--genpolicy-version", required=True)
    parser.add_argument("--cvm-measure-version", required=True)
    parser.add_argument("--previous-log-index", type=int, default=0)
    args = parser.parse_args()

    artifacts_dir = Path(args.artifacts_dir)
    cvm_artifacts_dir = Path(args.cvm_artifacts_dir)
    count = 0

    for model_dir in sorted(artifacts_dir.iterdir()):
        meas_file = model_dir / "measurements.json"
        rego_file = model_dir / "kata-policy.rego"
        initdata_file = model_dir / "initdata_b64.txt"

        if not meas_file.exists():
            continue

        meta_file = cvm_artifacts_dir / model_dir.name / "meta.json"
        if not meta_file.exists():
            print(f"WARNING: No meta.json for {model_dir.name}, skipping",
                  file=sys.stderr)
            continue

        meta = json.loads(meta_file.read_text())

        measurements = json.loads(meas_file.read_text())
        rego_policy = rego_file.read_text() if rego_file.exists() else ""
        initdata_hash = sha256_file(initdata_file) if initdata_file.exists() else ""

        predicate = build_predicate(
            model=model_dir.name,
            measurements=measurements,
            policy_id=args.policy_id,
            rego_policy=rego_policy,
            initdata_hash=initdata_hash,
            previous_rekor_log_index=args.previous_log_index,
            release_version=args.version,
            genpolicy_version=args.genpolicy_version,
            cvm_measure_version=args.cvm_measure_version,
            firmware_ref=meta["firmware_ref"],
            uki_ref=meta["uki_ref"],
            baseline_ref=meta["baseline_ref"],
        )

        output = model_dir / "predicate.json"
        output.write_text(json.dumps(predicate, indent=2) + "\n")
        count += 1
        print(f"Built predicate for {model_dir.name}: {output}")

    if count == 0:
        print("ERROR: No model artifacts found", file=sys.stderr)
        sys.exit(1)

    print(f"Generated {count} predicate(s)")


if __name__ == "__main__":
    main()
