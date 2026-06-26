#!/usr/bin/env python3
"""Delete an ITA attestation policy by ID.

Reads configuration from environment variables:
  POLICY_ID, ITA_API_KEY, ITA_API_URL

Prints "existed=true" if the policy was deleted, "existed=false" if not found.
"""

from __future__ import annotations

import os
import sys

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def ita_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session


def main() -> None:
    policy_id = os.environ["POLICY_ID"]
    api_key = os.environ["ITA_API_KEY"]
    api_url = os.environ["ITA_API_URL"]

    print(f"Deleting ITA policy: {policy_id}", file=sys.stderr)

    url = f"{api_url}/management/v1/policies/{policy_id}"

    resp = ita_session().delete(url, headers={
        "Accept": "application/json",
        "x-api-key": api_key,
    })

    if resp.ok:
        print(f"Policy deleted: {policy_id} (HTTP {resp.status_code})", file=sys.stderr)
        print("existed=true")
    elif resp.status_code == 404:
        print(f"Policy already deleted or not found: {policy_id} (HTTP 404)", file=sys.stderr)
        print("existed=false")
    else:
        print(f"ERROR: ITA API returned HTTP {resp.status_code}", file=sys.stderr)
        print(resp.text, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
