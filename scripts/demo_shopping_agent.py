#!/usr/bin/env python3
"""
Tesht (Pramana) — Shopping Agent Demo

Demonstrates:
  • User creates a shopping agent and delegates purchase authority
  • Agent creates an AP2 intent mandate (shopping goal)
  • Agent creates a cart mandate (specific transaction)
  • Merchant verifies the full chain: delegation ✓, mandate ✓

No server required. Pure SDK, runs in < 5 seconds.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Locate SDK relative to this script (repo root / sdk / python)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "python"))

from tesht.commerce import issue_cart_mandate, issue_intent_mandate, verify_mandate
from tesht.delegation import issue_delegation, verify_delegation_chain
from tesht.identity import AgentIdentity

PASS = "✅"
FAIL = "❌"


def main() -> int:
    errors: list[str] = []
    print("\n🛍️  Tesht (Pramana) — Shopping Agent Demo\n" + "─" * 48)

    # ── 1. Identities ──────────────────────────────────────────────────────
    print("\nStep 1 │ Creating identities …")
    alice = AgentIdentity.create("alice")
    agent = AgentIdentity.create("shopping-agent")
    merchant = AgentIdentity.create("nike-merchant")
    print(f"  {PASS} Alice (user)      {alice.did[:40]}…")
    print(f"  {PASS} Shopping agent    {agent.did[:40]}…")
    print(f"  {PASS} Nike merchant     {merchant.did[:40]}…")

    # ── 2. Delegation: user → agent ────────────────────────────────────────
    print("\nStep 2 │ Alice delegates purchase authority to agent …")
    delegation_jwt = issue_delegation(
        delegator=alice,
        delegate_did=agent.did,
        scope={"actions": ["purchase"], "max_amount": 2000000, "currency": "USD"},
        max_depth=1,
        ttl_seconds=3600,
    )
    print(f"  {PASS} Delegation JWT issued (scope: purchase up to $20,000)")

    # ── 3. AP2 Intent mandate ──────────────────────────────────────────────
    print('\nStep 3 │ Agent creates intent mandate ("running shoes under $120") …')
    intent_jwt = issue_intent_mandate(
        delegator=agent,
        agent_did=agent.did,
        intent={
            "description": "running shoes under $120",
            "category": "footwear",
            "max_amount": 12000,
            "currency": "USD",
        },
        ttl_seconds=3600,
    )
    print(f"  {PASS} Intent mandate issued (max: $120.00 USD)")

    # ── 4. Cart mandate ────────────────────────────────────────────────────
    print("\nStep 4 │ Agent adds item to cart and creates cart mandate …")
    cart_jwt = issue_cart_mandate(
        delegator=agent,
        agent_did=agent.did,
        cart={
            "merchant": "Nike",
            "items": [{"name": "Nike Air Max 270", "qty": 1, "unit_price": 8999}],
            "total": {"value": 8999, "currency": "USD"},
        },
        intent_mandate_jwt=intent_jwt,
        ttl_seconds=300,
    )
    print(f"  {PASS} Cart mandate issued (Nike Air Max 270 × 1 = $89.99 USD)")

    # ── 5. Merchant verifies delegation chain ──────────────────────────────
    print("\nStep 5 │ Merchant verifies delegation chain …")
    chain_result = verify_delegation_chain(delegation_jwt, required_action="purchase")
    if chain_result.verified:
        print(f"  {PASS} Delegation chain valid (depth={chain_result.depth}, "
              f"scope={chain_result.effective_scope})")
    else:
        msg = f"Delegation chain verification failed: {chain_result.reason}"
        print(f"  {FAIL} {msg}")
        errors.append(msg)

    # ── 6. Merchant verifies cart mandate ──────────────────────────────────
    print("\nStep 6 │ Merchant verifies cart mandate …")
    mandate_result = verify_mandate(cart_jwt)
    if mandate_result.verified:
        print(f"  {PASS} Cart mandate valid (type={mandate_result.mandate_type}, "
              f"id={mandate_result.mandate_id[:16]}…)")
    else:
        msg = f"Cart mandate verification failed: {mandate_result.reason}"
        print(f"  {FAIL} {msg}")
        errors.append(msg)

    # ── Audit trail ────────────────────────────────────────────────────────
    print("\n" + "─" * 48 + "\nAudit Trail\n" + "─" * 48)
    print(f"  User DID       {alice.did}")
    print(f"  Agent DID      {agent.did}")
    print(f"  Merchant DID   {merchant.did}")
    print(f"  Scope          purchase ≤ $20,000 USD (delegated by Alice)")
    print(f"  Intent         running shoes ≤ $120 USD")
    print(f"  Cart           Nike Air Max 270 × 1 = $89.99 USD")
    print(f"  Chain depth    {chain_result.depth if chain_result.verified else 'N/A'}")
    print(f"  Mandate ID     {mandate_result.mandate_id[:32]}…" if mandate_result.verified else "  Mandate ID     N/A")
    print("─" * 48)

    if errors:
        print(f"\n{FAIL} Demo failed — {len(errors)} error(s):")
        for e in errors:
            print(f"  • {e}")
        return 1

    print(f"\n{PASS} Demo complete. All verifications passed. ✅\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
