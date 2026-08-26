#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://127.0.0.1:5051}"
KC_BASE="${KC_BASE:-http://127.0.0.1:8080}"
REALM="${KC_REALM:-tesht}"
CLIENT_ID="${KC_CLIENT_ID:-tesht-api}"
USERNAME="${KC_USERNAME:-demo-user}"
PASSWORD="${KC_PASSWORD:-demo}"

TOKEN=$(curl -sSf -X POST "$KC_BASE/realms/$REALM/protocol/openid-connect/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "username=$USERNAME" \
  --data-urlencode "password=$PASSWORD" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

echo "Calling workflow demo..."

curl -sSf -X POST "$API_BASE/v1/workflows/drift-demo" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{}' \
  | python3 -m json.tool
