#!/usr/bin/env python3
"""Delete the ITA RIMs named in RIM_NAMES (whitespace-separated).

One list call maps names to IDs. A name ITA does not hold is skipped rather
than failed, so the delete is idempotent.

Reads configuration from environment variables:
  RIM_NAMES, ITA_API_KEY, ITA_API_URL

Prints "deleted=<count>" to stdout for the action shell to capture.
"""

from __future__ import annotations

import os
import sys

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
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session


def check(resp: requests.Response, action: str) -> None:
    if not resp.ok:
        print(f"ERROR: {action}: ITA API returned HTTP {resp.status_code}",
              file=sys.stderr)
        print(resp.text, file=sys.stderr)
        sys.exit(1)


def main() -> None:
    names = os.environ.get("RIM_NAMES", "").split()
    api_key = os.environ["ITA_API_KEY"]
    api_url = os.environ["ITA_API_URL"]

    url = f"{api_url}/management/v1/rims"
    headers = {"Accept": "application/json", "x-api-key": api_key}
    session = ita_session()

    resp = session.get(
        url,
        params={"excludeContent": "true"},
        headers=headers,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    check(resp, "list RIMs")
    ids = {rim["name"]: rim["id"] for rim in resp.json()}

    deleted = 0
    for name in names:
        if name not in ids:
            print(f"RIM already gone: {name}", file=sys.stderr)
            continue
        print(f"Deleting RIM: {name}", file=sys.stderr)
        resp = session.delete(
            f"{url}/{ids[name]}",
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if resp.status_code != 404:
            check(resp, f"delete RIM {name}")
            deleted += 1

    print(f"deleted={deleted}")


if __name__ == "__main__":
    main()
