#!/usr/bin/env python3
"""End-to-end dogfood of the agentic-commerce flow.

Boots the backend in-process (TestClient) against a throwaway SQLite DB and
walks the exact path the /agentic-commerce browser page uses:

  demo token -> storefront catalog -> authorize agent (budget + merchant
  allowlist) -> allowed purchase -> trust drop / step-up -> step-up complete
  + retry -> cumulative budget block -> merchant-allowlist block -> revoke
  (kill-switch) -> post-revoke deny.

No real payments; purchases are Session authorization decisions.

Run:  python3 scripts/dogfood_agentic_commerce.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

# Configure a clean, isolated dev environment BEFORE importing app modules.
_db = os.path.join(tempfile.mkdtemp(prefix="tesht_dogfood_"), "commerce.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_db}"
os.environ.setdefault("AUTH_JWT_SECRET", "dogfood-secret")
os.environ.setdefault("AUTH_JWT_ISSUER", "tesht-dogfood")
os.environ["TESHT_ENV"] = "development"
os.environ["GATEWAY_ENV"] = ""

from fastapi.testclient import TestClient  # noqa: E402

import main as main_mod  # noqa: E402

# Schema is created by the app's own startup (init_db → alembic upgrade) against
# the fresh SQLite file configured above; we deliberately do NOT pre-create it.


def money(cents):
    return "—" if cents is None else f"${cents/100:.2f}"


def hdr(title):
    print(f"\n\033[1m=== {title} ===\033[0m")


def show(label, resp):
    ok = resp.status_code < 400
    tick = "\033[92m✓\033[0m" if ok else "\033[91m✗\033[0m"
    print(f"{tick} {label}  [{resp.status_code}]")
    if not ok:
        print(f"   body: {resp.text[:500]}")
    return resp.json() if ok else None


def decision_line(d):
    col = {"allow": "\033[92m", "step_up": "\033[93m", "block": "\033[91m"}.get(d["decision"], "")
    budget = (d.get("factors") or {}).get("budget")
    extra = f" · remaining {money(budget.get('remaining'))}" if isinstance(budget, dict) else ""
    print(f"   {col}{d['decision'].upper()}\033[0m — {d.get('reason') or d.get('error_code')}{extra}")


def main() -> int:
    with TestClient(main_mod.app) as c:
        hdr("0 · Demo session (same call the browser makes)")
        tok = show("POST /v1/demo/session", c.post("/v1/demo/session", json={}))
        auth = {"Authorization": f"Bearer {tok['token']}"}

        hdr("1 · Storefront catalog")
        cat = show("GET /v1/storefront/products", c.get("/v1/storefront/products", headers=auth))
        products = {p["id"]: p for p in cat["products"]}
        for p in cat["products"]:
            print(f"   {p['image']} {p['name']:<18} {money(p['price']):>8}  ({p['merchant_name']})")

        hdr("2 · Human authorizes a shopping agent (budget $300, Nike only)")
        agent = show("POST /v1/agents", c.post("/v1/agents", json={"name": "dogfood-agent"}, headers=auth))
        sess = show(
            "POST /v1/sessions (packs: core+commerce)",
            c.post(
                "/v1/sessions",
                headers=auth,
                json={
                    "agent_did": agent["did"],
                    "human_did": "did:example:alice",
                    "scope": {
                        "actions": ["purchase"],
                        "max_amount": 30000,  # $300.00
                        "currency": "USD",
                        "merchants": ["nike-store"],
                    },
                    "packs": ["core", "commerce"],
                    "ttl_seconds": 3600,
                },
            ),
        )
        sid = sess["id"]
        print(f"   session {sid} · status {sess['status']} · packs {sess['packs']}")

        def buy(pid, simulate_score):
            p = products[pid]
            return c.post(
                f"/v1/sessions/{sid}/actions",
                headers=auth,
                json={
                    "action": "purchase",
                    "amount": p["price"],
                    "currency": p["currency"],
                    "merchant": p["merchant"],
                    "simulate_score": simulate_score,
                },
            )

        hdr("3 · Agent buys Air Max — high trust → ALLOW")
        decision_line(show("buy nike-airmax", buy("nike-airmax", 90)))

        hdr("4 · Agent buys Pegasus — trust dropped → STEP-UP")
        decision_line(show("buy nike-pegasus", buy("nike-pegasus", 60)))
        show("POST /v1/sessions/{id}/step_up", c.post(f"/v1/sessions/{sid}/step_up", headers=auth, json={"metadata": {"challenge": "human_present"}}))
        print("   human approved step-up → retry at restored trust")
        decision_line(show("retry nike-pegasus", buy("nike-pegasus", 90)))

        hdr("5 · Agent tries a 3rd item — would exceed $300 cumulative budget → BLOCK")
        # spent so far: 8999 (Air Max) + 12999 (Pegasus) = 21998; +12999 = 34997 > 30000
        decision_line(show("buy nike-pegasus again", buy("nike-pegasus", 90)))

        hdr("6 · Agent tries Apple Store (not in allowlist) → BLOCK")
        decision_line(show("buy apple-airpods", buy("apple-airpods", 90)))

        hdr("7 · Spend ledger (AP2) for this session")
        spend = show(f"GET /v1/commerce/mandates/{sid}/spend", c.get(f"/v1/commerce/mandates/{sid}/spend", headers=auth))
        print(f"   fulfillments={spend['fulfillments']} cumulative={spend['cumulative_spend']}")

        hdr("8 · Human pulls the kill-switch → REVOKE")
        show("POST /v1/sessions/{id}/revoke", c.post(f"/v1/sessions/{sid}/revoke", headers=auth, json={"cascade": True, "reason": "done"}))
        decision_line(show("buy after revoke", buy("nike-airmax", 90)))

        print("\n\033[1mDogfood complete — all agentic-commerce actions exercised.\033[0m")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
