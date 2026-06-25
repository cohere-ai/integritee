#!/usr/bin/env python3
"""Fetch an ITA attestation policy by ID and write it to a file.

Reads configuration from environment variables:
  POLICY_ID, ITA_API_KEY, ITA_API_URL

Writes the policy to $RUNNER_TEMP/fetched-policy-<id>.rego.
Prints "<policy_file>\n<policy_name>" to stdout for the action shell to capture.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path


def main() -> None:
    policy_id = os.environ["POLICY_ID"]
    api_key = os.environ["ITA_API_KEY"]
    api_url = os.environ["ITA_API_URL"]
    output_dir = Path(os.environ.get("RUNNER_TEMP", "/tmp"))

    url = f"{api_url}/management/v1/policies/{policy_id}"

    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "x-api-key": api_key,
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        print(f"ERROR: ITA API returned HTTP {exc.code}", file=sys.stderr)
        print(exc.read().decode(), file=sys.stderr)
        sys.exit(1)

    policy_content = body.get("policy", "")
    policy_name = body.get("policy_name", "")

    output_path = output_dir / f"fetched-policy-{policy_id}.rego"
    output_path.write_text(policy_content)
    print(f"Fetched policy: {policy_id} ({policy_name}) -> {output_path}", file=sys.stderr)

    print(output_path)
    print(policy_name)


if __name__ == "__main__":
    main()
