#!/usr/bin/env python3
"""Create or update an ITA attestation policy.

The policy is named POLICY_NAME, or integritee-<SHA-256 prefix of its
content> if unset. If POLICY_ID is set, that policy is overwritten; if not,
the policy with this name is created, or reused if it already has this
content. Nothing is written when ITA already holds the content.

ITA refuses a second policy with the same name or the same content (ignoring
whitespace), so any other collision fails with ITA's error.

Reads configuration from environment variables:
  POLICY_FILE, POLICY_NAME, ITA_API_KEY, ITA_API_URL, POLICY_ID,
  PREDICATE_FILE

Prints "policy-id=<id>" and "policy-hash=<ITA policy_hash>" to stdout for the
action shell to capture.
"""

from __future__ import annotations

import hashlib
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


def check(resp: requests.Response) -> dict:
    if not resp.ok:
        print(f"ERROR: ITA API returned HTTP {resp.status_code}", file=sys.stderr)
        print(resp.text, file=sys.stderr)
        sys.exit(1)
    return resp.json()


def policy_name_for(content: str) -> str:
    return f"integritee-{hashlib.sha256(content.encode()).hexdigest()[:16]}"


def main() -> None:
    policy_file = Path(os.environ["POLICY_FILE"])
    api_key = os.environ["ITA_API_KEY"]
    api_url = os.environ["ITA_API_URL"]
    policy_id = os.environ.get("POLICY_ID", "")
    predicate_file = os.environ.get("PREDICATE_FILE", "")

    if not policy_file.is_file():
        print(f"ERROR: Policy file not found: {policy_file}", file=sys.stderr)
        sys.exit(1)

    policy_content = policy_file.read_text()
    policy_name = (
        os.environ.get("POLICY_NAME") or policy_name_for(policy_content)
    )

    url = f"{api_url}/management/v1/policies"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }
    session = ita_session()

    if policy_id:
        current = check(session.get(
            f"{url}/{policy_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        ))
    else:
        # ITA ignores an unknown filter and returns every policy, so the
        # name is checked here rather than trusted to the query.
        named = check(session.get(
            url,
            params={"policyName": policy_name},
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        ))
        current = next(
            (p for p in named if p.get("policy_name") == policy_name), None
        )

    if current and current.get("policy") == policy_content:
        print(f"Policy unchanged: {policy_name}", file=sys.stderr)
        response_body = current
    elif policy_id:
        print(f"Updating policy {policy_id}: {policy_name}", file=sys.stderr)
        response_body = check(session.put(
            f"{url}/{policy_id}",
            json={
                "policy_id": policy_id,
                "policy_name": policy_name,
                "policy": policy_content,
            },
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        ))
    else:
        print(f"Creating policy: {policy_name}", file=sys.stderr)
        response_body = check(session.post(
            url,
            json={
                "policy_name": policy_name,
                "attestation_type": "Composite Attestation",
                "service_offer_id": TEE_SERVICE_OFFER_ID,
                "policy": policy_content,
            },
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        ))

    policy_id = response_body.get("policy_id") or policy_id
    print(f"Policy ID: {policy_id}", file=sys.stderr)

    if predicate_file:
        path = Path(predicate_file)
        if path.is_file():
            predicate = json.loads(path.read_text())
            predicate["policy_id"] = policy_id
            path.write_text(json.dumps(predicate, indent=2) + "\n")
            print(f"Updated predicate: {predicate_file}", file=sys.stderr)

    print(f"policy-id={policy_id}")
    print(f"policy-hash={response_body.get('policy_hash', '')}")


if __name__ == "__main__":
    main()
