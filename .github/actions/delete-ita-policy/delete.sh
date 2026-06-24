#!/usr/bin/env bash
# Delete an ITA attestation policy by ID.
set -euo pipefail

POLICY_ID="${POLICY_ID:?POLICY_ID is required}"
API_KEY="${ITA_API_KEY:?ITA_API_KEY is required}"
API_URL="${ITA_API_URL:?ITA_API_URL is required}"

echo "Deleting ITA policy: $POLICY_ID" >&2

RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE \
  "${API_URL}/management/v1/policies/${POLICY_ID}" \
  -H "Accept: application/json" \
  -H "x-api-key: ${API_KEY}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then
  echo "ERROR: ITA API returned HTTP $HTTP_CODE" >&2
  echo "$RESPONSE_BODY" >&2
  exit 1
fi

echo "Policy deleted: $POLICY_ID" >&2
