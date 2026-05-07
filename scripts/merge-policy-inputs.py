#!/usr/bin/env python3
"""Merge base and per-model genpolicy inputs.

genpolicy accepts a single rules file (-p) and a single settings file (-j).
This script merges the shared base files with optional per-model overrides
so that model-specific files only need to declare what they change.

Rego merge semantics:
  - Parse both files for `default X := Y` lines
  - Per-model defaults override base defaults (same variable name)
  - Non-default lines from the per-model file are appended after the base
  - Package declaration, imports, and comments from the base are preserved

Settings JSON merge semantics:
  - Recursive deep merge: per-model keys win at every nesting level
  - Arrays are replaced wholesale (not concatenated)
  - Missing per-model keys fall through to base values

Usage:
    python merge-policy-inputs.py \
        --base-rules rules/rules.rego \
        --base-settings rules/genpolicy-settings.json \
        --model-dir models/command-r-plus \
        --output-dir artifacts/command-r-plus
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_PATTERN = re.compile(r"^default\s+(\w+)\s*:=")


def parse_rego(text: str) -> tuple[list[str], dict[str, str], list[str]]:
    """Split a Rego file into preamble, default declarations, and extra rules.

    Returns:
        preamble: package/import/comment lines before the first default
        defaults: {variable_name: full_line} preserving declaration order
        extras: non-default, non-preamble lines (complex rule blocks, etc.)
    """
    preamble: list[str] = []
    defaults: dict[str, str] = {}
    extras: list[str] = []
    seen_default = False

    for line in text.splitlines():
        match = DEFAULT_PATTERN.match(line)
        if match:
            seen_default = True
            defaults[match.group(1)] = line
        elif not seen_default:
            preamble.append(line)
        else:
            extras.append(line)

    return preamble, defaults, extras


def merge_rego(base_text: str, override_text: str) -> str:
    """Merge base Rego with per-model overrides.

    Per-model `default X := Y` lines replace the base value for X.
    Any non-default lines in the override file are appended at the end.
    """
    base_preamble, base_defaults, base_extras = parse_rego(base_text)
    _, override_defaults, override_extras = parse_rego(override_text)

    merged_defaults = {**base_defaults, **override_defaults}

    lines = list(base_preamble)
    for var_name in merged_defaults:
        lines.append(merged_defaults[var_name])

    if base_extras:
        lines.extend(base_extras)

    if override_extras:
        stripped = [l for l in override_extras if l.strip()]
        if stripped:
            lines.append("")
            lines.append("# --- Per-model rules ---")
            lines.extend(override_extras)

    if not lines[-1:] == [""]:
        lines.append("")

    return "\n".join(lines)


def deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Override wins at leaf level."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def merge_settings(base_text: str, override_text: str) -> str:
    """Merge base settings JSON with per-model overrides via deep merge."""
    base = json.loads(base_text)
    override = json.loads(override_text)
    merged = deep_merge(base, override)
    return json.dumps(merged, indent=2) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge base + per-model genpolicy inputs")
    parser.add_argument("--base-rules", required=True, help="Path to base rules.rego")
    parser.add_argument("--base-settings", required=True, help="Path to base genpolicy-settings.json")
    parser.add_argument("--model-dir", required=True, help="Path to model directory (may contain overrides)")
    parser.add_argument("--output-dir", required=True, help="Output directory for merged files")
    args = parser.parse_args()

    base_rules_path = Path(args.base_rules)
    base_settings_path = Path(args.base_settings)
    model_dir = Path(args.model_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    base_rules = base_rules_path.read_text()
    model_rules_path = model_dir / "rules.rego"
    if model_rules_path.exists():
        merged_rules = merge_rego(base_rules, model_rules_path.read_text())
        print(f"Merged rules: base + {model_rules_path}")
    else:
        merged_rules = base_rules
        print(f"Using base rules (no model override)")

    (output_dir / "merged-rules.rego").write_text(merged_rules)

    base_settings = base_settings_path.read_text()
    model_settings_path = model_dir / "genpolicy-settings.json"
    if model_settings_path.exists():
        merged_settings = merge_settings(base_settings, model_settings_path.read_text())
        print(f"Merged settings: base + {model_settings_path}")
    else:
        merged_settings = base_settings
        print(f"Using base settings (no model override)")

    (output_dir / "merged-settings.json").write_text(merged_settings)


if __name__ == "__main__":
    main()
