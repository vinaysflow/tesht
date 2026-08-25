# Dogfood: Agentic Commerce

A real, end-to-end product surface for **agentic commerce**: a human authorizes a
shopping agent with a budget + merchant allowlist, the agent shops a mock
storefront, and **every purchase is gated** by the Pramana authorization Session
composed with AP2 mandates:

```
scope (actions/currency)  →  merchant allowlist  →  cumulative budget (AP2)  →  trust  →  decision
```

No real money moves — purchases are **authorization decisions**, not settlement.

## What "all actions" means here

| Action | Where | Result |
|--------|-------|--------|
| Human → agent handoff | `POST /v1/sessions` (packs `core`+`commerce`) | active session with budget + merchant allowlist |
| Browse storefront | `GET /v1/storefront/products` | mock catalog (Nike / Apple / Acme Books) |
| Purchase (allowed) | `POST /v1/sessions/{id}/actions` | `allow`, records spend, budget depletes |
| Purchase (low trust) | same | `step_up` — human approval required |
| Complete step-up + retry | `POST /v1/sessions/{id}/step_up` | trust restored → purchase proceeds |
| Purchase over budget | same | `block` (`mandate_exceeded`) — cumulative budget enforced |
| Purchase at unlisted merchant | same | `block` (`scope_denied`) — merchant allowlist enforced |
| Spend ledger | `GET /v1/commerce/mandates/{session_id}/spend` | cumulative AP2 spend |
| Revoke (kill-switch) | `POST /v1/sessions/{id}/revoke` | all further actions denied |

The `commerce` pack is what turns on cumulative-budget + merchant enforcement; a
plain `core` session keeps the original per-action scope behavior.

## Fastest proof (no servers, ~1s)

Runs the whole journey in-process against a throwaway SQLite DB and prints a transcript:

```bash
python3 scripts/dogfood_agentic_commerce.py
```

## Full browser dogfood

1. **Backend** (from repo root):
   ```bash
   cp .env.example .env   # first time
   make dev               # backend on :5051, frontend on :6080
   ```
   Or backend only:
   ```bash
   cd backend && uvicorn main:app --reload --port 5051
   ```

2. **Frontend** (if not using `make dev`):
   ```bash
   cd frontend && NEXT_PUBLIC_API_URL=http://localhost:5051 npm run dev
   ```

3. Open **`/agentic-commerce`** (e.g. http://localhost:3000/agentic-commerce or
   http://127.0.0.1:6080/agentic-commerce). The page:
   - fetches a demo token (`POST /v1/demo/session`, same as the dashboard),
   - lets you set a **budget** and **merchant allowlist**, then **authorize** an agent,
   - shows a storefront where the agent buys items,
   - has a **simulated trust selector** (dev only) to exercise allow / step-up / block,
   - shows a live **budget meter**, a **step-up modal**, a **revoke kill-switch**, and a **decision activity feed**.

## Dev-only trust simulation

To demonstrate the step-up and block branches deterministically in a browser,
`POST /v1/sessions/{id}/actions` accepts an optional `simulate_score` (0–100).
It is **honored only in development** and only when the session has no real
scored credential, so production behavior is never affected — there, trust comes
from the credential / gateway behavioral path and unscored sessions fail safe to
step-up.

## Production note

Set `PRAMANA_ENV=production` (+ Postgres `DATABASE_URL`) to run the same flow with
production-safe defaults (fail-closed status checks, durable audit, unscored
sessions → step-up). See [`DEPLOYMENT.md`](DEPLOYMENT.md).
