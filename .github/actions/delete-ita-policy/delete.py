#!/usr/bin/env python3
"""Delete an ITA attestation policy by ID.

Reads configuration from environment variables:
  POLICY_ID, ITA_API_KEY, ITA_API_URL
"""

from __future__ import annotations

import os
import sys
import urllib.request


def main() -> None:
    policy_id = os.environ["POLICY_ID"]
    api_key = os.environ["ITA_API_KEY"]
    api_url = os.environ["ITA_API_URL"]

    print(f"Deleting ITA policy: {policy_id}", file=sys.stderr)

    req = urllib.request.Request(
        f"{api_url}/management/v1/policies/{policy_id}",
        method="DELETE",
        headers={
            "Accept": "application/json",
            "x-api-key": api_key,
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            print(f"Policy deleted: {policy_id} (HTTP {resp.status})", file=sys.stderr)
            print("existed=true")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print(f"Policy already deleted or not found: {policy_id} (HTTP 404)", file=sys.stderr)
            print("existed=false")
        else:
            print(f"ERROR: ITA API returned HTTP {exc.code}", file=sys.stderr)
            print(exc.read().decode(), file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
