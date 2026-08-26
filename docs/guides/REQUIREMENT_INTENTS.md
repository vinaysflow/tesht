## Requirement Intents (one API to rule them all)

This API is inspired by Stripe’s “Intent” pattern: create a single object representing a trust requirement request, then confirm it to produce a **decision** and an optional **portable proof bundle** (VC JWTs).

### 0) Get a demo token

After `make dev` (API at `http://127.0.0.1:5051`):

```bash
BASE=http://127.0.0.1:5051
TOKEN=$(curl -sSf -X POST $BASE/v1/demo/session -H 'content-type: application/json' -d '{}' | python -c 'import sys, json; print(json.load(sys.stdin)["token"])')
```

### 1) Create an intent

```bash
curl -sSf -X POST $BASE/v1/requirement_intents \
  -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -H "Idempotency-Key: demo-create-001" \
  -d '{
    "issuer_name": "walmart-procurement-agent",
    "subject_name": "supplier-api-agent",
    "requirements": [
      { "id": "cap_negotiate_contracts", "type": "CapabilityCredential",
        "claims": { "capability": "negotiate_contracts", "max_amount": 100000 }
      }
    ],
    "options": { "ttl_seconds": 3600 },
    "metadata": { "demo": true }
  }' | python -m json.tool
```

Copy the returned `id`.

### 2) Confirm the intent (hybrid: decision + proof bundle)

```bash
INTENT_ID="<paste-id-here>"
curl -sSf -X POST $BASE/v1/requirement_intents/$INTENT_ID/confirm \
  -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -H "Idempotency-Key: demo-confirm-001" \
  -d '{"return_mode":"both","ttl_seconds":3600}' | python -m json.tool
```

Expected:
- `decision.status` is `satisfied`
- `proof_bundle.credentials[0].vc_jwt` is present (portable proof)

### 3) Retrieve (polling pattern)

```bash
curl -sSf $BASE/v1/requirement_intents/$INTENT_ID \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

### Notes
- **Idempotency**: reuse the same `Idempotency-Key` to safely retry on network failures. Reusing the key with a different payload returns HTTP 409.
- **Always-issue-fresh**: `confirm` issues fresh credentials for the intent’s requirements.



