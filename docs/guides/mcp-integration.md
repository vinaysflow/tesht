# MCP Integration Guide

Tesht (Pramana) provides a drop-in authentication layer for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. Agents authenticate by presenting a cryptographically signed Verifiable Presentation (VP) instead of API keys or OAuth tokens.

## How it works

```
Agent                           MCP Server
  │                                 │
  │  create_presentation(vcs, aud)  │
  │  ──────────────────────────────►│
  │  Authorization: Bearer <VP-JWT> │
  │                                 │  verify_presentation()
  │                                 │  check trusted_issuers
  │                                 │  check required_types
  │◄────────────────────────────────│
  │  MCPAuthResult(authenticated)   │
```

## Installation

```bash
pip install -e sdk/python   # includes tesht.integrations.mcp
```

## Server-side setup

### 1. Create the server identity and configure auth

```python
from tesht.identity import AgentIdentity
from tesht.integrations.mcp import MCPAuthConfig, TeshtMCPAuth

# Server identity — its DID becomes the VP audience
server = AgentIdentity.create("my-mcp-server", method="key")

auth = TeshtMCPAuth(
    MCPAuthConfig(
        identity=server,

        # Only trust credentials issued by these DIDs
        # Empty list = trust any issuer (not recommended for production)
        trusted_issuers=["did:key:z6Mk...", "did:web:issuer.example.com"],

        # Every VP must contain at least one credential of this type
        required_credential_types=["MCPAccessCredential"],

        # Optionally require a delegation chain covering specific actions
        require_delegation=False,
        required_actions=[],
    )
)
```

### 2. Verify incoming requests

```python
headers = {"Authorization": "Bearer <VP-JWT>"}
result = auth.verify_request(headers)

if result.authenticated:
    print(f"Agent {result.agent_did} authenticated")
    print(f"Verified credentials: {len(result.credentials)}")
else:
    print(f"Denied: {result.reason}")
```

### `MCPAuthResult` fields

| Field | Type | Description |
|---|---|---|
| `authenticated` | `bool` | Whether the request was granted |
| `agent_did` | `str \| None` | DID of the authenticated agent |
| `agent_name` | `str \| None` | Name claim from the credential |
| `credentials` | `list[VerificationResult]` | All verified VCs from the VP |
| `delegation` | `DelegationResult \| None` | Delegation chain result if present |
| `scopes` | `list[str]` | Scopes extracted from delegation |
| `reason` | `str \| None` | Rejection reason if not authenticated |

### 3. FastAPI middleware

```python
from fastapi import FastAPI, Depends
from tesht.integrations.mcp import mcp_auth_middleware

app = FastAPI()
require_auth = mcp_auth_middleware(auth)

@app.post("/tools/execute")
async def execute_tool(auth_ctx=Depends(require_auth)):
    return {"agent": auth_ctx.agent_did, "result": "..."}
```

## Client-side setup

### 1. Issue a credential to the agent (one-time setup)

An authorised issuer must issue an `MCPAccessCredential` to the agent. The issuer's DID must be in the server's `trusted_issuers` list.

```python
from tesht.credentials import issue_vc

issuer = AgentIdentity.create("my-org-issuer")
agent  = AgentIdentity.create("my-agent")

access_vc = issue_vc(
    issuer=issuer,
    subject_did=agent.did,
    credential_type="MCPAccessCredential",
    claims={"tools": ["read", "write"], "tier": "standard"},
    ttl_seconds=86400,
)
```

### 2. Create a VP for each request

```python
from tesht.credentials import create_presentation

vp_jwt = create_presentation(
    holder=agent,
    credentials=[access_vc],
    audience=server.did,   # must match server's DID
    nonce="optional-replay-protection-nonce",
)

headers = {"Authorization": f"Bearer {vp_jwt}"}
```

### 3. With delegation

If the server requires `require_delegation=True`, include a delegation JWT in the credentials list:

```python
from tesht.delegation import issue_delegation

delegation_jwt = issue_delegation(
    delegator=user,
    delegate_did=agent.did,
    scope={"actions": ["execute_tool", "read_resource"]},
    max_depth=1,
)

vp_jwt = create_presentation(
    holder=agent,
    credentials=[access_vc, delegation_jwt],
    audience=server.did,
)
```

## `MCPAuthConfig` reference

| Field | Type | Default | Description |
|---|---|---|---|
| `identity` | `AgentIdentity` | required | Server's own identity (sets VP audience) |
| `trusted_issuers` | `list[str]` | `[]` | Trusted issuer DIDs. Empty = trust all |
| `required_credential_types` | `list[str]` | `[]` | All types must appear in the VP |
| `require_delegation` | `bool` | `False` | Require a valid `DelegationCredential` |
| `required_actions` | `list[str]` | `[]` | Actions that must be in the delegation scope |

## Running the demo

```bash
python scripts/demo_mcp_auth.py
```

Expected output: authorized agent is granted, unauthorized (self-signed) agent is denied. Both assertions exit 0.

## See also

- [docs/guides/delegation.md](delegation.md) — delegation chain mechanics
- [docs/architecture.md](../architecture.md) — MCP auth flow diagram
