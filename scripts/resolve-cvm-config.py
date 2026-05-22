#!/usr/bin/env python3
"""Resolve per-model CVM config from each model's cvm-config.yaml.

Writes a meta.json for each model under <output-dir>/<model>/meta.json.

Usage:
    python resolve-cvm-config.py \
        --models model-a,model-b \
        --models-dir models/ \
        --output-dir cvm-artifacts/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

REQUIRED_FIELDS = ("machine_type", "podvm_image_tag", "ram_gib")


def resolve_model(model: str, models_dir: Path) -> dict:
    config_path = models_dir / model / "cvm-config.yaml"

    if not config_path.exists():
        raise FileNotFoundError(
            f"Missing required cvm-config.yaml for model '{model}' "
            f"(expected at {config_path})"
        )

    with open(config_path) as f:
        config = yaml.safe_load(f) or {}

    missing = [f for f in REQUIRED_FIELDS if f not in config]
    if missing:
        raise ValueError(
            f"cvm-config.yaml for model '{model}' is missing required "
            f"field(s): {', '.join(missing)}"
        )

    return {f: config[f] for f in REQUIRED_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve per-model CVM config")
    parser.add_argument("--models", required=True, help="Comma-separated model names")
    parser.add_argument("--models-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    models_dir = Path(args.models_dir)
    output_dir = Path(args.output_dir)

    for model in args.models.split(","):
        model = model.strip()
        if not model:
            continue

        meta = resolve_model(model, models_dir)

        model_out = output_dir / model
        model_out.mkdir(parents=True, exist_ok=True)
        meta_path = model_out / "meta.json"
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)
            f.write("\n")

        print(f"{model}: machine_type={meta['machine_type']} "
              f"podvm_image_tag={meta['podvm_image_tag']} "
              f"ram_gib={meta['ram_gib']}")


if __name__ == "__main__":
    main()
