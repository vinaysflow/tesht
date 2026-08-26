#!/usr/bin/env python3
"""
Tesht (Pramana) — Multi-Agent Supply Chain Demo

Demonstrates:
  • Cross-organisation credential issuance (Acme CA → Acme Supplier)
  • Walmart delegates supplier-verification authority to a sub-agent
  • Sub-agent verifies the supplier credential
  • Full delegation chain provenance printed

No server required. Pure SDK, runs in < 5 seconds.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "python"))

from tesht.credentials import issue_vc, verify_vc
from tesht.delegation import issue_delegation, delegate_further, verify_delegation_chain
from tesht.identity import AgentIdentity

PASS = "✅"
FAIL = "❌"


def main() -> int:
    errors: list[str] = []
    print("\n🏭  Tesht (Pramana) — Multi-Agent Supply Chain Demo\n" + "─" * 56)

    # ── 1. Identities ──────────────────────────────────────────────────────
    print("\nStep 1 │ Creating identities …")
    walmart_procurement = AgentIdentity.create("walmart-procurement")
    verification_agent  = AgentIdentity.create("supplier-verification-agent")
    acme_ca             = AgentIdentity.create("acme-certification-authority")
    acme_supplier       = AgentIdentity.create("acme-electronics-supplier")
    print(f"  {PASS} Walmart Procurement Agent   {walmart_procurement.did[:36]}…")
    print(f"  {PASS} Supplier Verification Agent {verification_agent.did[:36]}…")
    print(f"  {PASS} Acme Certification Authority {acme_ca.did[:36]}…")
    print(f"  {PASS} Acme Electronics Supplier   {acme_supplier.did[:36]}…")

    # ── 2. Acme CA issues ISO 27001 compliance credential to Acme Supplier ─
    print("\nStep 2 │ Acme CA issues ISO 27001 compliance credential …")
    compliance_jwt = issue_vc(
        issuer=acme_ca,
        subject_did=acme_supplier.did,
        credential_type="ISO27001ComplianceCredential",
        claims={
            "standard": "ISO/IEC 27001:2022",
            "scope": "Information security management",
            "certified_by": "Acme Certification Authority",
            "valid_until": "2027-01-01",
            "categories": ["electronics", "manufacturing"],
        },
        ttl_seconds=86400,
    )
    print(f"  {PASS} ISO 27001 credential issued by Acme CA to Acme Supplier")

    # ── 3. Verify the compliance credential ───────────────────────────────
    print("\nStep 3 │ Verifying Acme's compliance credential …")
    vc_result = verify_vc(compliance_jwt)
    if vc_result.verified:
        print(f"  {PASS} Credential valid (type={vc_result.credential_type}, "
              f"issuer=…{vc_result.issuer_did[-24:]})")
    else:
        msg = f"Credential verification failed: {vc_result.reason}"
        print(f"  {FAIL} {msg}")
        errors.append(msg)

    # ── 4. Walmart delegates supplier-verification authority ───────────────
    print("\nStep 4 │ Walmart delegates supplier-verification authority …")
    root_delegation_jwt = issue_delegation(
        delegator=walmart_procurement,
        delegate_did=verification_agent.did,
        scope={
            "actions": ["verify_supplier", "request_audit"],
            "categories": ["electronics", "manufacturing"],
            "max_depth": 2,
        },
        max_depth=2,
        ttl_seconds=86400,
    )
    print(f"  {PASS} Root delegation issued: Walmart → Verification Agent")
    print(f"       Scope: verify_supplier, request_audit | categories: electronics, manufacturing")

    # ── 5. Verification agent sub-delegates to a specialist auditor ────────
    print("\nStep 5 │ Verification agent sub-delegates to specialist auditor …")
    auditor = AgentIdentity.create("specialist-auditor")
    sub_delegation_jwt = delegate_further(
        holder=verification_agent,
        parent_delegation_jwt=root_delegation_jwt,
        sub_delegate_did=auditor.did,
        narrowed_scope={
            "actions": ["verify_supplier"],
            "categories": ["electronics"],
        },
        ttl_seconds=3600,
    )
    print(f"  {PASS} Sub-delegation issued: Verification Agent → Specialist Auditor")
    print(f"       Narrowed scope: verify_supplier only | categories: electronics")

    # ── 6. Verify the full delegation chain ────────────────────────────────
    print("\nStep 6 │ Verifying full delegation chain …")
    chain_result = verify_delegation_chain(
        sub_delegation_jwt,
        required_action="verify_supplier",
    )
    if chain_result.verified:
        print(f"  {PASS} Delegation chain valid (depth={chain_result.depth})")
        print(f"       Effective scope: {chain_result.effective_scope}")
    else:
        msg = f"Chain verification failed: {chain_result.reason}"
        print(f"  {FAIL} {msg}")
        errors.append(msg)

    # ── Provenance summary ─────────────────────────────────────────────────
    print("\n" + "─" * 56 + "\nChain Provenance\n" + "─" * 56)
    print(f"  Origin            Walmart Procurement Agent")
    print(f"                    {walmart_procurement.did}")
    print(f"  Delegation 1      → Supplier Verification Agent (depth 1)")
    print(f"                    {verification_agent.did}")
    print(f"  Delegation 2      → Specialist Auditor (depth 2)")
    print(f"                    {auditor.did}")
    print(f"  Chain depth       {chain_result.depth if chain_result.verified else 'N/A'}")
    print(f"  Effective scope   {chain_result.effective_scope if chain_result.verified else 'N/A'}")
    print(f"\n  Credential Provenance")
    print(f"  Issuer            Acme Certification Authority")
    print(f"                    {acme_ca.did}")
    print(f"  Subject           Acme Electronics Supplier")
    print(f"                    {acme_supplier.did}")
    print(f"  Standard          ISO/IEC 27001:2022")
    print(f"  Credential valid  {vc_result.verified}")
    print("─" * 56)

    if errors:
        print(f"\n{FAIL} Demo failed — {len(errors)} error(s):")
        for e in errors:
            print(f"  • {e}")
        return 1

    print(f"\n{PASS} Demo complete. All verifications passed. ✅\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
