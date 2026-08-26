#!/usr/bin/env python3
"""
Tesht (Pramana) — Blended Identity Demo
=========================================

Demonstrates VP-Based Blended Identity: every agent request carries BOTH the
agent's own identity AND the human delegator's identity as a single W3C
Verifiable Presentation — cryptographically bound, fully portable.

Competitor approach (Aembit): proprietary composite identity fused at runtime.
Tesht approach: W3C VP-JWT bundling multiple VC-JWTs → portable + open.

Steps:
  1  Create 4 identities  (Alice, ShoppingAgent, MCP Server, Acme Corp IdP)
  2  IdP issues credentials to Alice and the agent
  3  Alice delegates purchase authority to ShoppingAgent
  4  Agent composes a Blended Identity VP
  5  MCP Server verifies — both identities extracted
  6  Rejection demo — no delegator identity VC blocked by policy

No server required. Pure SDK, runs in < 2 seconds.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "python"))

from tesht.credentials import (
    create_blended_presentation,
    issue_vc,
    verify_blended_presentation,
)
from tesht.delegation import issue_delegation
from tesht.identity import AgentIdentity
from tesht.integrations.mcp import MCPAuthConfig, TeshtMCPAuth

# ── Terminal colours ──────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
DIM    = "\033[2m"

PASS = f"{GREEN}✓{RESET}"
FAIL = f"{RED}✗{RESET}"
ARROW = f"{CYAN}→{RESET}"


def banner(text: str) -> None:
    width = 62
    print(f"\n{BOLD}{'─' * width}{RESET}")
    print(f"{BOLD}  {text}{RESET}")
    print(f"{BOLD}{'─' * width}{RESET}")


def section(n: int, title: str) -> None:
    print(f"\n{CYAN}{BOLD}Step {n}{RESET}  {BOLD}{title}{RESET}")


def info(label: str, value: str) -> None:
    print(f"  {DIM}{label:<28}{RESET} {value}")


def ok(msg: str) -> None:
    print(f"  {PASS}  {msg}")


def fail(msg: str) -> None:
    print(f"  {FAIL}  {RED}{msg}{RESET}")


def box(lines: list[str]) -> None:
    width = max(len(l) for l in lines) + 4
    print(f"  ╔{'═' * width}╗")
    for line in lines:
        pad = width - len(line) - 2
        print(f"  ║  {line}{' ' * pad}║")
    print(f"  ╚{'═' * width}╝")


def main() -> int:
    errors: list[str] = []

    banner("Tesht (Pramana) — Blended Identity Demo")
    print(f"\n  {DIM}W3C VP-JWTs bundle human + agent identity into one portable token.{RESET}")

    # ── Step 1: Create identities ─────────────────────────────────────────────
    section(1, "Creating identities …")

    acme_idp      = AgentIdentity.create("acme-corp-idp")
    alice         = AgentIdentity.create("alice-johnson")
    shopping_agent = AgentIdentity.create("shopping-agent")
    mcp_server    = AgentIdentity.create("product-catalog-mcp")

    info("Acme Corp IdP",     acme_idp.did[:52] + "…")
    info("Alice Johnson",     alice.did[:52] + "…")
    info("ShoppingAgent",     shopping_agent.did[:52] + "…")
    info("Product Catalog MCP", mcp_server.did[:52] + "…")
    ok("4 did:key identities created")

    # ── Step 2: IdP issues credentials ────────────────────────────────────────
    section(2, "Acme Corp IdP issues credentials …")

    alice_org_vc = issue_vc(
        issuer=acme_idp,
        subject_did=alice.did,
        credential_type="OrganizationalRoleCredential",
        claims={
            "name": "Alice Johnson",
            "email": "alice@acme.com",
            "department": "Procurement",
            "role": "Senior Buyer",
            "organization": "Acme Corp",
            "clearance_level": "HIGH",
        },
        ttl_seconds=86400,
    )
    agent_vc = issue_vc(
        issuer=acme_idp,
        subject_did=shopping_agent.did,
        credential_type="AgentCredential",
        claims={
            "agentName": "ShoppingBot",
            "agentType": "LLM Agent",
            "ownerOrg": "Acme Corp",
            "purpose": "Procurement automation",
        },
        ttl_seconds=86400,
    )

    ok("OrganizationalRoleCredential issued to Alice  (name, email, dept, role, clearance)")
    ok("AgentCredential issued to ShoppingAgent      (type, org, purpose)")

    # ── Step 3: Alice delegates to ShoppingAgent ──────────────────────────────
    section(3, "Alice delegates purchase authority to ShoppingAgent …")

    delegation_jwt = issue_delegation(
        delegator=alice,
        delegate_did=shopping_agent.did,
        scope={
            "actions": ["browse_products", "add_to_cart", "purchase"],
            "max_amount": 50000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": ["electronics", "office_supplies"],
        },
        max_depth=2,
        ttl_seconds=3600,
    )

    ok("DelegationCredential issued")
    info("  Scope.actions",  "browse_products, add_to_cart, purchase")
    info("  Scope.max_amount", "$500.00 USD")
    info("  Scope.merchants", "any (*)")

    # ── Step 4: Agent composes Blended Identity VP ────────────────────────────
    section(4, "ShoppingAgent composes Blended Identity VP …")

    blended_vp = create_blended_presentation(
        agent=shopping_agent,
        delegation_jwt=delegation_jwt,
        delegator_identity_jwt=alice_org_vc,
        additional_credentials=[agent_vc],
        audience=mcp_server.did,
        nonce="demo-nonce-42",
    )

    ok("BlendedIdentityPresentation VP-JWT created")
    info("  Bundle", "DelegationCredential + OrganizationalRoleCredential + AgentCredential")
    info("  Audience", mcp_server.did[:52] + "…")
    info("  Nonce", "demo-nonce-42")
    info("  TTL", "300s")

    # ── Step 5: MCP Server verifies ───────────────────────────────────────────
    section(5, "Product Catalog MCP verifies Blended Identity VP …")

    result = verify_blended_presentation(
        blended_vp,
        expected_audience=mcp_server.did,
        expected_nonce="demo-nonce-42",
    )

    if not result.verified:
        fail(f"Verification failed: {result.reason}")
        errors.append(f"Step 5 verification failed: {result.reason}")
    else:
        ok(f"VP verified  — blended={result.blended}")

        agent_cred_types  = [cr.credential_type for cr in result.agent_credentials]
        delg_cred_types   = [cr.credential_type for cr in result.delegator_credentials]
        scope_actions     = result.effective_scope.get("actions", [])
        scope_amount      = result.effective_scope.get("max_amount", 0)

        box([
            f"  {BOLD}BLENDED IDENTITY RESULT{RESET}",
            "",
            f"  Agent DID       {result.agent_did[:46]}…",
            f"  Agent creds     {', '.join(agent_cred_types) or '—'}",
            "",
            f"  Delegator DID   {(result.delegator_did or '—')[:46]}{'…' if result.delegator_did else ''}",
            f"  Delegator name  {result.delegator_claims.get('name', '—')}",
            f"  Delegator role  {result.delegator_claims.get('role', '—')}",
            f"  Delegator org   {result.delegator_claims.get('organization', '—')}",
            f"  Delegator creds {', '.join(delg_cred_types) or '—'}",
            "",
            f"  Delegation depth  {result.delegation.depth if result.delegation else 0}",
            f"  Effective scope   actions: {scope_actions}",
            f"                    max_amount: ${scope_amount / 100:.2f} USD",
            "",
            f"  Blended         {BOLD}{YELLOW}{result.blended}{RESET}",
            f"  Verified        {BOLD}{GREEN}{result.verified}{RESET}",
        ])

        # Verify MCP auth path with require_delegator_identity=True
        server_auth = TeshtMCPAuth(MCPAuthConfig(
            identity=mcp_server,
            require_delegation=True,
            require_delegator_identity=True,
            delegator_credential_types=["OrganizationalRoleCredential"],
        ))
        headers = {"Authorization": f"Bearer {blended_vp}"}
        mcp_result = server_auth.verify_request(headers)
        if mcp_result.authenticated:
            ok(f"TeshtMCPAuth  — authenticated={mcp_result.authenticated}  blended={mcp_result.blended}")
            info("  MCP delegator_did",    (mcp_result.delegator_did or "")[:52] + "…")
            info("  MCP delegator type",   mcp_result.delegator_credential_type or "—")
        else:
            fail(f"TeshtMCPAuth unexpectedly failed: {mcp_result.reason}")
            errors.append(f"Step 5 MCP auth failed: {mcp_result.reason}")

    # ── Step 6: Rejection demo ────────────────────────────────────────────────
    section(6, "Rejection demo — delegation without delegator identity VC …")

    # Build a VP with delegation only (no Alice OrgRoleVC)
    from tesht.credentials import create_presentation as _create_vp
    delegation_only_vp = _create_vp(
        holder=shopping_agent,
        credentials=[delegation_jwt],
        audience=mcp_server.did,
    )
    strict_auth = TeshtMCPAuth(MCPAuthConfig(
        identity=mcp_server,
        require_delegation=True,
        require_delegator_identity=True,
    ))
    reject_result = strict_auth.verify_request({"Authorization": f"Bearer {delegation_only_vp}"})

    if not reject_result.authenticated:
        ok(f"Rejected as expected  — authenticated={reject_result.authenticated}")
        info("  Reason", reject_result.reason or "")
    else:
        fail("Agent without delegator identity VC was incorrectly ACCEPTED")
        errors.append("Step 6: delegation-only VP should have been rejected")

    # Also show that credential type filter works
    type_filter_auth = TeshtMCPAuth(MCPAuthConfig(
        identity=mcp_server,
        require_delegation=True,
        require_delegator_identity=True,
        delegator_credential_types=["EnterpriseIdentityCredential"],  # wrong type
    ))
    type_filter_result = type_filter_auth.verify_request({"Authorization": f"Bearer {blended_vp}"})

    if not type_filter_result.authenticated:
        ok(f"Credential type filter — rejected as expected")
        info("  Reason", type_filter_result.reason or "")
    else:
        fail("Wrong delegator credential type was incorrectly accepted")
        errors.append("Step 6: wrong delegator credential type should have been rejected")

    # ── Summary ───────────────────────────────────────────────────────────────
    banner("Demo Complete")
    if errors:
        for e in errors:
            fail(e)
        print(f"\n  {RED}{BOLD}{len(errors)} error(s). See above.{RESET}\n")
        return 1

    print(f"\n  {GREEN}{BOLD}All steps passed.{RESET}")
    print(f"\n  {DIM}Key insight: one VP-JWT carries BOTH identities — agent + human delegator.")
    print(f"  Any W3C-compliant verifier can extract, verify, and act on both.")
    print(f"  No proprietary runtime. No vendor lock-in. Pure open standards.{RESET}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
