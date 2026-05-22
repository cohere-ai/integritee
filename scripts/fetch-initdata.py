#!/usr/bin/env python3
"""Fetch pre-built initdata from blobheart for each model.

Retrieves the kata-policy-patch.yaml from the blobheart repo for each model,
extracts the base64-encoded cc_init_data annotation, and writes it to
artifacts/<model>/initdata_b64.txt for downstream use by cvm-measure.

Model name mapping: <model_name>-cc in the blobheart directory structure.

Requires BLOBHEART_REPO, BLOBHEART_REF, BLOBHEART_INITDATA_DIR, and
GH_TOKEN environment variables.

Usage:
    python fetch-initdata.py \
        --models model-a,model-b \
        --artifacts-dir artifacts/
"""

from __future__ import annotations

import argparse
import base64
import os
import subprocess
import sys
from pathlib import Path

import yaml


def fetch_initdata(repo: str, ref: str, initdata_dir: str, model: str) -> str:
    blobheart_name = f"{model}-cc"
    api_path = (
        f"/repos/{repo}/contents/"
        f"{initdata_dir}/{blobheart_name}/kata-policy-patch.yaml"
        f"?ref={ref}"
    )

    result = subprocess.run(
        ["gh", "api", api_path, "--jq", ".content"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(
            f"ERROR: Failed to fetch initdata for {model} "
            f"(blobheart path: {blobheart_name}): {result.stderr.strip()}",
            file=sys.stderr,
        )
        sys.exit(1)

    raw_yaml = base64.b64decode(result.stdout.strip()).decode()
    doc = yaml.safe_load(raw_yaml)

    annotations = (
        doc.get("spec", {})
        .get("template", {})
        .get("metadata", {})
        .get("annotations", {})
    )
    initdata = annotations.get(
        "io.katacontainers.config.hypervisor.cc_init_data"
    )
    if not initdata:
        print(
            f"ERROR: No cc_init_data annotation found in "
            f"kata-policy-patch.yaml for {model}",
            file=sys.stderr,
        )
        sys.exit(1)

    return initdata


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch initdata from blobheart per model",
    )
    parser.add_argument(
        "--models", required=True, help="Comma-separated model names",
    )
    parser.add_argument("--artifacts-dir", required=True)
    args = parser.parse_args()

    repo = os.environ["BLOBHEART_REPO"]
    ref = os.environ["BLOBHEART_REF"]
    initdata_dir = os.environ["BLOBHEART_INITDATA_DIR"]
    artifacts_dir = Path(args.artifacts_dir)

    for model in args.models.split(","):
        model = model.strip()
        if not model:
            continue

        print(f"{model}: fetching initdata from blobheart ({model}-cc)")
        initdata_b64 = fetch_initdata(repo, ref, initdata_dir, model)

        model_artifacts = artifacts_dir / model
        model_artifacts.mkdir(parents=True, exist_ok=True)
        (model_artifacts / "initdata_b64.txt").write_text(initdata_b64)
        print(f"{model}: wrote initdata_b64.txt ({len(initdata_b64)} chars)")

    print("Initdata fetch complete")


if __name__ == "__main__":
    main()
