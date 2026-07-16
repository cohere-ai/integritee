#!/usr/bin/env python3
"""Create or update an ITA attestation policy.

If POLICY_ID is set: PUT (update existing).
If POLICY_ID is empty: POST (create new), outputs the new policy_id.

Reads configuration from environment variables:
  POLICY_FILE, POLICY_NAME, SERVICE_OFFER_ID,
  ITA_API_KEY, ITA_API_URL, POLICY_ID, PREDICATE_FILE
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# "TEE Attestation" service offer on api.trustauthority.intel.com
TEE_SERVICE_OFFER_ID = "d47f9540-5bd6-47ff-b984-5fcf0d74c6e2"
REQUEST_TIMEOUT_SECONDS = 30


def ita_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session


def main() -> None:
    policy_file = Path(os.environ["POLICY_FILE"])
    policy_name = os.environ["POLICY_NAME"]
    api_key = os.environ["ITA_API_KEY"]
    api_url = os.environ["ITA_API_URL"]
    policy_id = os.environ.get("POLICY_ID", "")
    predicate_file = os.environ.get("PREDICATE_FILE", "")

    if not policy_file.is_file():
        print(f"ERROR: Policy file not found: {policy_file}", file=sys.stderr)
        sys.exit(1)

    policy_content = policy_file.read_text()

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }

    session = ita_session()

    if policy_id:
        print(f"Updating existing policy: {policy_id} ({policy_name})", file=sys.stderr)
        payload = {
            "policy_id": policy_id,
            "policy_name": policy_name,
            "policy": policy_content,
        }
        url = f"{api_url}/management/v1/policies/{policy_id}"
        resp = session.put(
            url,
            json=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    else:
        print(f"Creating new policy: {policy_name}", file=sys.stderr)
        payload = {
            "policy_name": policy_name,
            "attestation_type": "Composite Attestation",
            "service_offer_id": TEE_SERVICE_OFFER_ID,
            "policy": policy_content,
        }
        url = f"{api_url}/management/v1/policies"
        resp = session.post(
            url,
            json=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

    if not resp.ok:
        print(f"ERROR: ITA API returned HTTP {resp.status_code}", file=sys.stderr)
        print(resp.text, file=sys.stderr)
        sys.exit(1)

    response_body = resp.json()

    if not policy_id:
        policy_id = response_body.get("policy_id", "")

    print(f"Policy ID: {policy_id}", file=sys.stderr)

    if predicate_file:
        path = Path(predicate_file)
        if path.is_file():
            predicate = json.loads(path.read_text())
            predicate["policy_id"] = policy_id
            path.write_text(json.dumps(predicate, indent=2) + "\n")
            print(f"Updated predicate: {predicate_file}", file=sys.stderr)

    print(policy_id)


if __name__ == "__main__":
    main()
