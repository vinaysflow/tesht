### Developer quickstart + feedback (Tesht Demo)

Base URL:
- https://aurviaglobal-tesht-demo.hf.space

Start here (UI):
- https://aurviaglobal-tesht-demo.hf.space/demo

Docs:
- One-API (Stripe-like): `docs/guides/REQUIREMENT_INTENTS.md`
- Reviewer runbook: `docs/guides/HF_REVIEWER_RUNBOOK.md`

---

## 1) Get a demo token (no login)

IMPORTANT: In Hugging Face discussions, code fences must start at the beginning of the line (no indentation).

```bash
BASE=https://aurviaglobal-tesht-demo.hf.space
TOKEN=$(curl -sSf -X POST "$BASE/v1/demo/session" \
  -H "content-type: application/json" \
  -d '{}' | python -c 'import sys, json; print(json.load(sys.stdin)["token"])')
echo "TOKEN ready"
```

---

## 2) One-API flow: RequirementIntent (create → confirm → retrieve)

### 2.1 Create an intent

```bash
curl -sSf -X POST "$BASE/v1/requirement_intents" \
  -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -H "Idempotency-Key: demo-create-001" \
  -d '{
    "issuer_name": "walmart-procurement-agent",
    "subject_name": "supplier-api-agent",
    "requirements": [
      {
        "id": "cap_negotiate_contracts",
        "type": "CapabilityCredential",
        "claims": { "capability": "negotiate_contracts", "max_amount": 100000 }
      }
    ],
    "metadata": { "demo": true }
  }' | python -m json.tool
```

Copy the returned `"id"` into `INTENT_ID`.

### 2.2 Confirm (hybrid: decision + proof bundle)

```bash
INTENT_ID="<PASTE_INTENT_ID_HERE>"
curl -sSf -X POST "$BASE/v1/requirement_intents/$INTENT_ID/confirm" \
  -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -H "Idempotency-Key: demo-confirm-001" \
  -d '{"return_mode":"both","ttl_seconds":3600}' | python -m json.tool
```

Expected:
- `status` = `succeeded`
- `decision.status` = `satisfied`
- `proof_bundle.credentials[0].vc_jwt` exists (portable proof)

### 2.3 Retrieve (poll)

```bash
curl -sSf "$BASE/v1/requirement_intents/$INTENT_ID" \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

---

## 3) Guided demo (UI)

- Open: https://aurviaglobal-tesht-demo.hf.space/demo
- Click **Run Drift Demo**
- Expected: `verify_before.verified=true` and `verify_after.reason=revoked`

---

## Feedback (reply in the Community thread)

Please include:
- What you expected vs what happened
- Your browser + OS
- Timestamp (UTC)
- Any `request_id` shown in the error message



