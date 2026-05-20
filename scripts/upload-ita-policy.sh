#!/usr/bin/env bash
# Update an existing ITA attestation policy slot (blue/green) via PUT.
#
# Usage:
#   ./upload-ita-policy.sh \
#     --policy-file artifacts/ita-attestation-policy.rego \
#     --policy-name "model-integrity-policy-a" \
#     --policy-id "cbeedffa-e224-4664-b6b4-573fcd4133d3" \
#     --api-url "$ITA_API_URL" \
#     --api-key "$ITA_ADMIN_API_KEY"
#
# ITA REST API docs:
#   https://docs.trustauthority.intel.com/main/articles/articles/ita/restapi/restapi-policy-management.html

set -euo pipefail

POLICY_FILE=""
POLICY_NAME=""
POLICY_ID=""
API_URL=""
API_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --policy-file) POLICY_FILE="$2"; shift 2 ;;
    --policy-name) POLICY_NAME="$2"; shift 2 ;;
    --policy-id)   POLICY_ID="$2"; shift 2 ;;
    --api-url)     API_URL="$2"; shift 2 ;;
    --api-key)     API_KEY="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

for var in POLICY_FILE POLICY_NAME POLICY_ID API_URL API_KEY; do
  if [[ -z "${!var}" ]]; then
    echo "ERROR: --$(echo "$var" | tr '[:upper:]' '[:lower:]' | tr '_' '-') is required" >&2
    exit 1
  fi
done

if [[ ! -f "$POLICY_FILE" ]]; then
  echo "ERROR: Policy file not found: $POLICY_FILE" >&2
  exit 1
fi

POLICY_CONTENT=$(cat "$POLICY_FILE")

BODY=$(python3 -c "
import json, sys
print(json.dumps({
    'policy_id': sys.argv[1],
    'policy_name': sys.argv[2],
    'policy': sys.argv[3],
}))
" "$POLICY_ID" "$POLICY_NAME" "$POLICY_CONTENT")

echo "Updating ITA policy ${POLICY_ID} (${POLICY_NAME})" >&2

RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
  "${API_URL}/management/v1/policies/${POLICY_ID}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${API_KEY}" \
  -d "$BODY")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then
  echo "ERROR: ITA API returned HTTP $HTTP_CODE" >&2
  echo "$RESPONSE_BODY" >&2
  exit 1
fi

echo "Policy updated successfully: $POLICY_ID" >&2
