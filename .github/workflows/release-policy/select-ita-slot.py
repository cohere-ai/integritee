"""Select which ITA blue/green policy slot to target.

Checks the latest GitHub release for the slot used last time,
then picks the OTHER slot. Defaults to slot-a if no prior release
is found. Prints policy_slot, policy_id, and policy_name as
key=value lines to stdout.
"""

import os
import re
import subprocess
import sys

SLOTS = {
    "slot-a": {
        "id": "cbeedffa-e224-4664-b6b4-573fcd4133d3",
        "name": "integritee-policy-a",
    },
    "slot-b": {
        "id": "ecdf9171-2f85-47b4-9941-703118f731a8",
        "name": "integritee-policy-b",
    },
}

def detect_last_slot() -> str:
    try:
        body = subprocess.check_output(
            ["gh", "release", "view", "--json", "body", "-q", ".body"],
            stderr=subprocess.DEVNULL,
        ).decode()
    except subprocess.CalledProcessError:
        return ""
    m = re.search(r"ITA Policy Slot.*?`(slot-[ab])", body)
    return m.group(1) if m else ""


def main() -> None:
    override = os.environ.get("ITA_SLOT_OVERRIDE", "").strip()

    if override and override != "auto":
        print(f"Slot override: {override}", file=sys.stderr)
        target = override
    else:
        last = detect_last_slot()
        print(f"Last release used: {last or 'none detected'}", file=sys.stderr)
        target = "slot-b" if last == "slot-a" else "slot-a"

    slot = SLOTS[target]
    print(f"Targeting: {target} ({slot['name']} / {slot['id']})", file=sys.stderr)

    print(f"policy_slot={target}")
    print(f"policy_id={slot['id']}")
    print(f"policy_name={slot['name']}")


if __name__ == "__main__":
    main()
