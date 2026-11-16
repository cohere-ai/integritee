#!/usr/bin/env python3
"""Delete ITA RIMs and policies under the prefixes that a release predicate
does not record, or with WARN_ONLY=true only warn about them.

A failed release can leave them behind. Policies go first, so no policy is
left importing a deleted RIM.

Reads configuration from environment variables:
  RIM_PREFIX, POLICY_PREFIX, PREDICATE_FILE, WARN_ONLY, ITA_API_KEY,
  ITA_API_URL
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

REQUEST_TIMEOUT_SECONDS = 30


def ita_session() -> requests.Session:
    # As for uploads, ITA answers 409 while it serializes concurrent RIM
    # writes, and neither 409 nor 429 applies the delete.
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=2,
        status_forcelist=[409, 429],
        allowed_methods=None,
        raise_on_status=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session


def check(resp: requests.Response, action: str) -> None:
    if not resp.ok:
        print(f"ERROR: {action}: ITA API returned HTTP {resp.status_code}",
              file=sys.stderr)
        print(resp.text, file=sys.stderr)
        sys.exit(1)


def orphans(
    rims: list[dict],
    policies: list[dict],
    rim_prefix: str,
    policy_prefix: str,
    predicate: dict,
) -> list[tuple[str, str, str]]:
    """(kind, label, ID) of each orphan, policies first."""
    return [
        *(
            ("policies", f"policy {policy['policy_name']}",
             policy["policy_id"])
            for policy in policies
            if policy.get("policy_name", "").startswith(policy_prefix)
            and policy["policy_id"] != predicate["policy_id"]
        ),
        *(
            ("rims", f"RIM {rim['name']}", rim["id"])
            for rim in rims
            if rim["name"].startswith(rim_prefix)
            and rim["name"] not in predicate["ita_rims"]
        ),
    ]


def main() -> None:
    predicate = json.loads(Path(os.environ["PREDICATE_FILE"]).read_text())
    if not predicate.get("policy_id") or not predicate.get("ita_rims"):
        print("ERROR: the predicate records no ITA policy or RIMs, so "
              "everything would be an orphan", file=sys.stderr)
        sys.exit(1)
    warn_only = os.environ.get("WARN_ONLY") == "true"
    url = f"{os.environ['ITA_API_URL']}/management/v1"
    headers = {
        "Accept": "application/json",
        "x-api-key": os.environ["ITA_API_KEY"],
    }
    session = ita_session()

    def get(kind: str, **params: str) -> list[dict]:
        resp = session.get(
            f"{url}/{kind}",
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        check(resp, f"list {kind}")
        return resp.json()

    found = orphans(
        get("rims", excludeContent="true"),
        get("policies"),
        os.environ["RIM_PREFIX"],
        os.environ["POLICY_PREFIX"],
        predicate,
    )
    for kind, label, id_ in found:
        if warn_only:
            print(f"::warning::ITA holds {label}, which the release does not "
                  "record; delete it by hand if nothing uses it")
            continue
        print(f"Deleting orphaned {label}", file=sys.stderr)
        resp = session.delete(
            f"{url}/{kind}/{id_}",
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if resp.status_code != 404:
            check(resp, f"delete {label}")
    print(f"{len(found)} orphan(s) in ITA", file=sys.stderr)


if __name__ == "__main__":
    main()
