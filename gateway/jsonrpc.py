"""
gateway.jsonrpc
~~~~~~~~~~~~~~~
JSON-RPC 2.0 envelope parsing for MCP traffic.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class JSONRPCRequest:
    """Parsed JSON-RPC 2.0 request."""

    id: Any
    method: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class JSONRPCResponse:
    """JSON-RPC 2.0 response."""

    id: Any
    result: Optional[Any] = None
    error: Optional[dict[str, Any]] = None


def parse_jsonrpc(body: bytes) -> JSONRPCRequest:
    """Parse a JSON-RPC 2.0 request from raw bytes.

    Raises ``ValueError`` on malformed input.
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("JSON-RPC request must be an object")

    jsonrpc_version = data.get("jsonrpc")
    if jsonrpc_version != "2.0":
        raise ValueError(f"Unsupported jsonrpc version: {jsonrpc_version}")

    method = data.get("method")
    if not isinstance(method, str) or not method:
        raise ValueError("Missing or invalid 'method' field")

    return JSONRPCRequest(
        id=data.get("id"),
        method=method,
        params=data.get("params") or {},
    )


def extract_tool_name(request: JSONRPCRequest) -> Optional[str]:
    """Extract the target tool or resource name from an MCP JSON-RPC request.

    - ``tools/call``    -> ``params.name``
    - ``resources/read`` -> ``params.uri``
    - Everything else   -> ``None`` (no specific tool targeted)
    """
    if request.method == "tools/call":
        return request.params.get("name")
    if request.method == "resources/read":
        return request.params.get("uri")
    return None


def is_tool_call(request: JSONRPCRequest) -> bool:
    """Return True if the request invokes a specific tool or resource."""
    return request.method in ("tools/call", "resources/read")


def build_jsonrpc_error(
    request_id: Any, code: int, message: str, data: Any = None
) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response dict."""
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}
