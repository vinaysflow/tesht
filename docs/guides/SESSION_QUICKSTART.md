# Session API Quickstart (< 15 minutes)

Pramana's authorization runtime: **handoff → tool call (decide) → step_up → revoke**.

## Prerequisites

```bash
make dev   # or: docker compose up -d
# API: http://127.0.0.1:5051
```

Get a token (demo mode):

```bash
BASE=http://127.0.0.1:5051
TOKEN=$(curl -sSf -X POST $BASE/v1/demo/session -H 'content-type: application/json' -d '{}' \
  | python -c 'import sys,json; print(json.load(sys.stdin)["token"])')
```

## 1. Create an agent

```bash
AGENT=$(curl -sSf -X POST $BASE/v1/agents \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"shopping-bot"}')
AGENT_DID=$(echo "$AGENT" | python -c 'import sys,json; print(json.load(sys.stdin)["did"])')
echo $AGENT_DID
```

## 2. Create a Session (handoff)

```bash
SESSION=$(curl -sSf -X POST $BASE/v1/sessions \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -H 'Idempotency-Key: demo-session-001' \
  -d "{
    \"agent_did\": \"$AGENT_DID\",
    \"human_did\": \"did:example:alice\",
    \"scope\": {\"actions\": [\"read_data\", \"purchase\"], \"max_amount\": 12000, \"currency\": \"USD\"},
    \"packs\": [\"core\"],
    \"ttl_seconds\": 3600
  }")
SESSION_ID=$(echo "$SESSION" | python -c 'import sys,json; print(json.load(sys.stdin)["id"])')
echo $SESSION_ID
```

## 3. Decide an action (tool call)

```bash
curl -sSf -X POST $BASE/v1/sessions/$SESSION_ID/actions \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"action":"read_data","tool_name":"query_database"}' | python -m json.tool
```

Expected: `"decision": "allow"` (or `step_up` / `block` based on trust score).

Out-of-scope is blocked:

```bash
curl -sSf -X POST $BASE/v1/sessions/$SESSION_ID/actions \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"action":"admin_wipe"}' | python -m json.tool
# error_code: scope_denied
```

## 4. Step-up (if required)

```bash
curl -sSf -X POST $BASE/v1/sessions/$SESSION_ID/step_up \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"metadata":{"challenge":"completed"}}' | python -m json.tool
```

## 5. Revoke

```bash
curl -sSf -X POST $BASE/v1/sessions/$SESSION_ID/revoke \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"cascade":true,"reason":"demo complete"}' | python -m json.tool
```

Further actions return `error_code: revoked`.

## Python SDK

```python
from pramana.client import PramanaClient

client = PramanaClient(base_url="http://127.0.0.1:5051", token=TOKEN)
session = client.create_session(
    agent_did=AGENT_DID,
    human_did="did:example:alice",
    scope={"actions": ["read_data"], "max_amount": 5000, "currency": "USD"},
    packs=["core"],
)
decision = client.decide(session["id"], action="read_data")
client.revoke_session(session["id"], reason="done")
```

## Stable error codes

| Code | Meaning |
|------|---------|
| `scope_denied` | Action not in session scope |
| `trust_step_up` | Trust too low — re-bind required |
| `mandate_exceeded` | Amount/currency exceeds scope |
| `revoked` | Session revoked |
| `expired` | Session TTL elapsed |
| `blocked` | Trust score below block threshold |
