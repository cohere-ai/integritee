"""Fetch a TDX baseline from cohere-cc-baselines by machine_type."""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path


def fetch_baseline(repo: str, machine_type: str, dest: Path) -> None:
    """Fetch a single baseline JSON file. Skips if dest already exists."""
    if dest.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    api_path = f"/repos/{repo}/contents/baselines/gcp/tdx/{machine_type}.json"
    result = subprocess.run(
        ["gh", "api", api_path, "--jq", ".content"],
        capture_output=True, text=True, check=True,
    )
    content = base64.b64decode(result.stdout.strip())
    dest.write_bytes(content)

    baseline = json.loads(content)
    fw = baseline["firmware_sha384"][:24]
    print(f"  Fetched baseline: firmware={fw}..., events={len(baseline['events'])}")
