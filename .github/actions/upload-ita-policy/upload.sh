#!/usr/bin/env bash
# Create or update an ITA attestation policy.
#
# If POLICY_ID is set: PUT (update existing).
# If POLICY_ID is empty: POST (create new), outputs the new policy_id.
set -euo pipefail

POLICY_FILE="${POLICY_FILE:?POLICY_FILE is required}"
POLICY_NAME="${POLICY_NAME:?POLICY_NAME is required}"
API_KEY="${ITA_API_KEY:?ITA_API_KEY is required}"
API_URL="${ITA_API_URL:?ITA_API_URL is required}"
POLICY_ID="${POLICY_ID:-}"

if [[ ! -f "$POLICY_FILE" ]]; then
  echo "ERROR: Policy file not found: $POLICY_FILE" >&2
  exit 1
fi

POLICY_CONTENT=$(cat "$POLICY_FILE")

if [[ -n "$POLICY_ID" ]]; then
  echo "Updating existing policy: $POLICY_ID ($POLICY_NAME)" >&2

  BODY=$(python3 -c "
import json, sys
print(json.dumps({
    'policy_id': sys.argv[1],
    'policy_name': sys.argv[2],
    'policy': sys.argv[3],
}))
" "$POLICY_ID" "$POLICY_NAME" "$POLICY_CONTENT")

  RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
    "${API_URL}/management/v1/policies/${POLICY_ID}" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -H "x-api-key: ${API_KEY}" \
    -d "$BODY")
else
  echo "Creating new policy: $POLICY_NAME" >&2

  BODY=$(python3 -c "
import json, sys
print(json.dumps({
    'policy_name': sys.argv[1],
    'policy_type': 'Appraisal policy - Rego',
    'policy': sys.argv[2],
}))
" "$POLICY_NAME" "$POLICY_CONTENT")

  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "${API_URL}/management/v1/policies" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -H "x-api-key: ${API_KEY}" \
    -d "$BODY")
fi

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then
  echo "ERROR: ITA API returned HTTP $HTTP_CODE" >&2
  echo "$RESPONSE_BODY" >&2
  exit 1
fi

if [[ -z "$POLICY_ID" ]]; then
  POLICY_ID=$(echo "$RESPONSE_BODY" | python3 -c "import json,sys; print(json.load(sys.stdin).get('policy_id',''))")
fi

echo "Policy ID: $POLICY_ID" >&2
echo "$POLICY_ID"
