"""
gateway.mock_mcp_server
~~~~~~~~~~~~~~~~~~~~~~~
Minimal MCP server for demo and testing.

Handles ``initialize``, ``tools/list``, and ``tools/call``.
Tracks received credentials so the demo can prove credential isolation
(the mock sees the gateway's API key, never the agent's VP).

Run standalone:
    uvicorn gateway.mock_mcp_server:app --host 0.0.0.0 --port 9100
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Mock MCP Server", version="1.0.0")

if os.getenv("PRAMANA_CORS_ENABLED", "").lower() in ("1", "true", "yes"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

received_requests: list[dict[str, Any]] = []


@app.post("/mcp")
async def handle_mcp(request: Request):
    """Handle MCP JSON-RPC 2.0 requests."""
    body: dict[str, Any] = await request.json()
    auth = request.headers.get("authorization", "none")
    api_key = request.headers.get("x-api-key", "none")

    received_requests.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": body.get("method"),
        "auth_header": auth[:30] + "..." if len(auth) > 30 else auth,
        "api_key_present": api_key != "none",
        "api_key_value": api_key[:12] + "***" if api_key != "none" else "none",
        "agent_did": request.headers.get("x-pramana-agent-did", "unknown"),
        "delegator": request.headers.get("x-pramana-delegator", "unknown"),
    })

    method = body.get("method", "")
    params = body.get("params", {})
    request_id = body.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "serverInfo": {"name": "Mock Database MCP", "version": "1.0"},
                "capabilities": {"tools": {}},
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "query_database",
                        "description": "Execute a read-only SQL query",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"sql": {"type": "string"}},
                        },
                    },
                    {
                        "name": "insert_record",
                        "description": "Insert a record into a table",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "table": {"type": "string"},
                                "data": {"type": "object"},
                            },
                        },
                    },
                    {
                        "name": "delete_record",
                        "description": "Delete a record from a table",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "table": {"type": "string"},
                                "id": {"type": "string"},
                            },
                        },
                    },
                ]
            },
        }

    if method == "tools/call":
        tool = params.get("name", "unknown")
        args = params.get("arguments", {})
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Mock result from {tool}: success (args={args})",
                    }
                ],
                "isError": False,
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"Unknown method: {method}"},
    }


@app.get("/credentials-received")
async def show_credentials():
    """Demo endpoint proving credential isolation."""
    return {"requests": received_requests}


@app.get("/health")
async def health():
    return {"status": "healthy", "requests_handled": len(received_requests)}
