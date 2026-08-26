# Hugging Face Reviewer Runbook (Tesht Demo)

## 60-second evaluation path

1) Open `/demo`
2) Wait for **Status: Session ready**
3) Click **Run Drift Demo**
4) Confirm:
   - `verify_before.verified` is `true`
   - `verify_after.verified` is `false` and `reason` is `revoked`

## What you are seeing

This demo creates a fresh, isolated tenant per visitor session, then runs an end-to-end flow:

- create issuer + subject DID agents (`did:web`)
- issue a VC-JWT (EdDSA)
- verify the VC, including revocation status via a **signed Bitstring Status List** VC-JWT
- revoke the credential (flip bit)
- verify again (should show revoked)

## Feedback (fast)

Please leave feedback in the Space **Community** tab (best), and include:

- What you expected to happen
- What happened instead
- Your browser + OS
- Timestamp (UTC)
- **Request ID** shown in the error message (if any)

## Useful endpoints

- `GET /health`
- `GET /ready`
- `POST /v1/demo/session`
- `POST /v1/workflows/drift-demo`
- `POST /v1/demo/reset`
- `GET /v1/demo/metrics` (demo-only)



