#!/usr/bin/env python3
"""Fetch TDX baselines from cohere-cc-baselines for each model.

Reads machine_type from each model's meta.json, fetches the corresponding
baseline via the GitHub API, and updates meta.json with the resolved paths.
Deduplicates by machine_type so identical baselines are fetched only once.

Requires GH_TOKEN and BASELINES_REPO environment variables.

Usage:
    python fetch-baselines.py \
        --models model-a,model-b \
        --cvm-artifacts-dir cvm-artifacts/
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
from pathlib import Path


def fetch_baseline(repo: str, machine_type: str, dest: Path) -> None:
    api_path = f"/repos/{repo}/contents/baselines/gcp/tdx/{machine_type}.json"
    result = subprocess.run(
        ["gh", "api", api_path, "--jq", ".content"],
        capture_output=True, text=True, check=True,
    )
    content = base64.b64decode(result.stdout.strip())
    dest.write_bytes(content)

    baseline = json.loads(content)
    fw = baseline["firmware_sha384"][:24]
    print(f"  firmware_sha384: {fw}..., events: {len(baseline['events'])}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch TDX baselines per model")
    parser.add_argument("--models", required=True, help="Comma-separated model names")
    parser.add_argument("--cvm-artifacts-dir", required=True)
    args = parser.parse_args()

    baselines_repo = os.environ["BASELINES_REPO"]
    cvm_dir = Path(args.cvm_artifacts_dir)
    baselines_dir = cvm_dir / "baselines"
    baselines_dir.mkdir(parents=True, exist_ok=True)

    for model in args.models.split(","):
        model = model.strip()
        if not model:
            continue

        meta_path = cvm_dir / model / "meta.json"
        meta = json.loads(meta_path.read_text())
        machine_type = meta["machine_type"]

        baseline_dest = baselines_dir / f"{machine_type}.json"
        baseline_ref = f"{baselines_repo}/baselines/gcp/tdx/{machine_type}.json"

        if baseline_dest.exists():
            print(f"{model}: reusing cached baseline for {machine_type}")
        else:
            print(f"{model}: fetching baseline for {machine_type}")
            fetch_baseline(baselines_repo, machine_type, baseline_dest)

        meta["baseline_path"] = str(baseline_dest)
        meta["baseline_ref"] = baseline_ref
        meta_path.write_text(json.dumps(meta, indent=2) + "\n")

    print("Baselines complete")


if __name__ == "__main__":
    main()
