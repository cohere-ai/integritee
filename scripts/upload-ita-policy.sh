#!/usr/bin/env bash
# Upload an ITA attestation policy and return the policy_id.
#
# Usage:
#   ./upload-ita-policy.sh \
#     --policy-file artifacts/ita-attestation-policy.rego \
#     --policy-name "model-integrity-v0.0.1" \
#     --api-url "$ITA_API_URL" \
#     --api-key "$ITA_ADMIN_API_KEY"
#
# Prints the policy_id to stdout on success.
#
# ITA REST API docs:
#   https://docs.trustauthority.intel.com/main/articles/articles/ita/restapi/restapi-policy-management.html

set -euo pipefail

POLICY_FILE=""
POLICY_NAME=""
API_URL=""
API_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --policy-file) POLICY_FILE="$2"; shift 2 ;;
    --policy-name) POLICY_NAME="$2"; shift 2 ;;
    --api-url)     API_URL="$2"; shift 2 ;;
    --api-key)     API_KEY="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

for var in POLICY_FILE POLICY_NAME API_URL API_KEY; do
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

# Base64-encode the policy for the ITA API
POLICY_B64=$(echo -n "$POLICY_CONTENT" | base64 | tr -d '\n')

BODY=$(cat <<EOF
{
  "policy_name": "$POLICY_NAME",
  "policy_type": "Appraisal policy",
  "attestation_type": "TDX",
  "policy": "$POLICY_B64"
}
EOF
)

echo "Uploading ITA policy: $POLICY_NAME" >&2

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  "${API_URL}/management/v1/policies" \
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

POLICY_ID=$(echo "$RESPONSE_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin)['policy_id'])")

echo "Policy uploaded successfully: $POLICY_ID" >&2
echo "$POLICY_ID"
