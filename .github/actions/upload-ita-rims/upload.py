#!/usr/bin/env python3
"""Create or update ITA RIMs from a directory of <rim name>.json files.

One list call finds the RIMs that already exist. It includes their content,
since ITA omits the hash from the content-free list. A RIM whose stored hash
matches its file is left alone, a missing one is created and a differing one
updated. Every write must return the file's hash, so ITA stores exactly the
rendered bytes. ITA serves a write after up to ~15 s; waiting for that is the
caller's job.

Reads configuration from environment variables:
  RIM_DIR, ITA_API_KEY, ITA_API_URL

Prints "written=<count>" to stdout for the action shell to capture.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

REQUEST_TIMEOUT_SECONDS = 30


def ita_session() -> requests.Session:
    # ITA answers 409 while it serializes concurrent RIM writes; neither 409
    # nor 429 applies the write, so retrying POST and PUT is safe. The last
    # response is returned rather than raised, so check() shows ITA's error.
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


def rim_hash(data: bytes) -> str:
    """ITA's RIM hash: base64 SHA-384 of the content as uploaded."""
    return base64.b64encode(hashlib.sha384(data).digest()).decode()


def check(resp: requests.Response, action: str) -> None:
    if not resp.ok:
        print(f"ERROR: {action}: ITA API returned HTTP {resp.status_code}",
              file=sys.stderr)
        print(resp.text, file=sys.stderr)
        sys.exit(1)


def main() -> None:
    rim_dir = Path(os.environ["RIM_DIR"])
    api_key = os.environ["ITA_API_KEY"]
    api_url = os.environ["ITA_API_URL"]

    files = sorted(rim_dir.glob("*.json"))
    if not files:
        print(f"ERROR: no RIM files in {rim_dir}", file=sys.stderr)
        sys.exit(1)

    url = f"{api_url}/management/v1/rims"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }
    session = ita_session()

    resp = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
    check(resp, "list RIMs")
    existing = {rim["name"]: rim for rim in resp.json()}
    unhashed = [name for name, rim in existing.items() if not rim.get("hash")]
    if unhashed:
        print(f"ERROR: ITA listed RIMs without a hash: {unhashed}",
              file=sys.stderr)
        sys.exit(1)

    written = 0
    for path in files:
        name = path.stem
        data = path.read_bytes()
        expected = rim_hash(data)
        rim = existing.get(name)

        if rim and rim["hash"] == expected:
            print(f"Unchanged RIM: {name}", file=sys.stderr)
            continue
        # requests serializes with json.dumps defaults, so ITA receives the
        # file's bytes in the file's key order.
        content = json.loads(data)
        if rim:
            print(f"Updating RIM: {name}", file=sys.stderr)
            resp = session.put(
                f"{url}/{rim['id']}",
                json={"content": content},
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        else:
            print(f"Creating RIM: {name}", file=sys.stderr)
            resp = session.post(
                url,
                json={"name": name, "content": content},
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        check(resp, f"write RIM {name}")

        stored = resp.json().get("hash")
        if stored != expected:
            print(f"ERROR: ITA stored RIM {name} with hash {stored}, "
                  f"expected {expected}", file=sys.stderr)
            sys.exit(1)
        written += 1

    print(f"written={written}")


if __name__ == "__main__":
    main()
