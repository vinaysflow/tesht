#!/usr/bin/env python3
"""
Tesht (Pramana) — MCP Authentication Demo

Demonstrates:
  • MCP server configured with Tesht identity-based auth
  • Authorized agent presents a Verifiable Presentation — access granted
  • Unauthorized agent presents a self-signed VP — access denied

No server required. Pure SDK, runs in < 5 seconds.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "python"))

from tesht.credentials import create_presentation, issue_vc
from tesht.identity import AgentIdentity
from tesht.integrations.mcp import MCPAuthConfig, TeshtMCPAuth

PASS = "✅"
FAIL = "❌"


def main() -> int:
    errors: list[str] = []
    print("\n🔐  Tesht (Pramana) — MCP Authentication Demo\n" + "─" * 50)

    # ── 1. Identities ──────────────────────────────────────────────────────
    print("\nStep 1 │ Creating identities …")
    mcp_server      = AgentIdentity.create("mcp-server")
    auth_agent      = AgentIdentity.create("authorized-agent")
    unauth_agent    = AgentIdentity.create("unauthorized-agent")
    print(f"  {PASS} MCP Server          {mcp_server.did[:40]}…")
    print(f"  {PASS} Authorized Agent    {auth_agent.did[:40]}…")
    print(f"  {PASS} Unauthorized Agent  {unauth_agent.did[:40]}…")

    # ── 2. Server issues credential to authorized agent ────────────────────
    print("\nStep 2 │ MCP server issues access credential to authorized agent …")
    access_vc_jwt = issue_vc(
        issuer=mcp_server,
        subject_did=auth_agent.did,
        credential_type="MCPAccessCredential",
        claims={
            "tools": ["read_data", "write_data", "execute_workflow"],
            "tier": "premium",
            "issued_by": "MCP Server",
        },
        ttl_seconds=3600,
    )
    print(f"  {PASS} MCPAccessCredential issued (tools: read_data, write_data, execute_workflow)")

    # ── 3. Configure MCP auth middleware ───────────────────────────────────
    print("\nStep 3 │ Configuring MCP auth middleware …")
    auth = TeshtMCPAuth(
        MCPAuthConfig(
            identity=mcp_server,
            trusted_issuers=[mcp_server.did],
            required_credential_types=["MCPAccessCredential"],
        )
    )
    print(f"  {PASS} Auth policy: trusted_issuers=[server DID], "
          f"required_types=[MCPAccessCredential]")

    # ── 4. Authorized agent — creates VP and requests access ───────────────
    print("\nStep 4 │ Authorized agent presents credentials …")
    auth_vp_jwt = create_presentation(
        holder=auth_agent,
        credentials=[access_vc_jwt],
        audience=mcp_server.did,
    )
    auth_result = auth.verify_request({"Authorization": f"Bearer {auth_vp_jwt}"})
    if auth_result.authenticated:
        print(f"  {PASS} Access GRANTED to {auth_agent.did[:36]}…")
        print(f"       Verified credentials: {len(auth_result.credentials)}")
        print(f"       Scopes: {auth_result.scopes or '(from credential claims)'}")
    else:
        msg = f"Authorized agent incorrectly rejected: {auth_result.reason}"
        print(f"  {FAIL} {msg}")
        errors.append(msg)

    # ── 5. Unauthorized agent — self-signed VP, not trusted ────────────────
    print("\nStep 5 │ Unauthorized agent presents self-signed credentials …")
    self_signed_vc = issue_vc(
        issuer=unauth_agent,
        subject_did=unauth_agent.did,
        credential_type="MCPAccessCredential",
        claims={"tools": ["read_data"], "tier": "self-claimed"},
        ttl_seconds=3600,
    )
    unauth_vp_jwt = create_presentation(
        holder=unauth_agent,
        credentials=[self_signed_vc],
        audience=mcp_server.did,
    )
    unauth_result = auth.verify_request({"Authorization": f"Bearer {unauth_vp_jwt}"})
    if not unauth_result.authenticated:
        print(f"  {PASS} Access DENIED for {unauth_agent.did[:36]}…")
        print(f"       Reason: {unauth_result.reason}")
    else:
        msg = "Unauthorized agent was incorrectly granted access"
        print(f"  {FAIL} {msg}")
        errors.append(msg)

    # ── Auth flow summary ──────────────────────────────────────────────────
    print("\n" + "─" * 50 + "\nAuth Flow Summary\n" + "─" * 50)
    print(f"  MCP Server DID       {mcp_server.did}")
    print(f"  Trusted issuers      [server DID above]")
    print(f"\n  Agent                Authorized Agent")
    print(f"  DID                  {auth_agent.did}")
    print(f"  Credential type      MCPAccessCredential (server-issued)")
    print(f"  Result               {'GRANTED' if auth_result.authenticated else 'DENIED'}")
    print(f"\n  Agent                Unauthorized Agent")
    print(f"  DID                  {unauth_agent.did}")
    print(f"  Credential type      MCPAccessCredential (self-signed)")
    print(f"  Result               {'GRANTED' if unauth_result.authenticated else 'DENIED'}")
    print("─" * 50)

    if errors:
        print(f"\n{FAIL} Demo failed — {len(errors)} error(s):")
        for e in errors:
            print(f"  • {e}")
        return 1

    print(f"\n{PASS} Demo complete. All verifications passed. ✅\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
