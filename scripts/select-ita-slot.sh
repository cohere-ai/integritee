#!/usr/bin/env bash
# Select which ITA blue/green policy slot to target.
#
# Checks the latest GitHub release for the slot used last time,
# then returns the OTHER slot. Defaults to slot-a if no prior
# release is found.
#
# Usage:
#   eval "$(./scripts/select-ita-slot.sh)"
#   echo "$ITA_POLICY_SLOT"  # slot-a | slot-b
#   echo "$ITA_POLICY_ID"   # UUID of the target slot
#   echo "$ITA_POLICY_NAME" # human-readable policy name
#
# The script prints shell variable assignments to stdout so the
# caller can eval them directly or parse them.

set -euo pipefail

SLOT_A_ID="cbeedffa-e224-4664-b6b4-573fcd4133d3"
SLOT_B_ID="ecdf9171-2f85-47b4-9941-703118f731a8"
SLOT_A_NAME="integritee-policy-a"
SLOT_B_NAME="integritee-policy-b"

if [[ -n "${ITA_SLOT_OVERRIDE:-}" ]]; then
  echo "Slot override: $ITA_SLOT_OVERRIDE" >&2
  TARGET_SLOT="$ITA_SLOT_OVERRIDE"
else
  LAST_SLOT=$(gh release view --json body -q '.body' 2>/dev/null \
    | grep -oP 'ITA Policy Slot.*?`\Kslot-[ab]' || echo "")

  echo "Last release used: ${LAST_SLOT:-none detected}" >&2

  if [[ "$LAST_SLOT" == "slot-a" ]]; then
    TARGET_SLOT="slot-b"
  else
    TARGET_SLOT="slot-a"
  fi
fi

if [[ "$TARGET_SLOT" == "slot-a" ]]; then
  TARGET_SLOT_ID="$SLOT_A_ID"
  TARGET_SLOT_NAME="$SLOT_A_NAME"
else
  TARGET_SLOT_ID="$SLOT_B_ID"
  TARGET_SLOT_NAME="$SLOT_B_NAME"
fi

echo "Targeting: $TARGET_SLOT ($TARGET_SLOT_NAME / $TARGET_SLOT_ID)" >&2

echo "ITA_POLICY_SLOT=$TARGET_SLOT"
echo "ITA_POLICY_ID=$TARGET_SLOT_ID"
echo "ITA_POLICY_NAME=$TARGET_SLOT_NAME"
