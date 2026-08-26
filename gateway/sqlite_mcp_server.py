"""
gateway.sqlite_mcp_server
~~~~~~~~~~~~~~~~~~~~~~~~~
Real SQLite-backed MCP server for the Tesht demo.

Replaces the canned-response mock_mcp_server.py with a server that executes
actual SQL queries against a SQLite database containing realistic product and
order data.

JSON-RPC 2.0 tools exposed:
  - query_database   : execute a SELECT query, returns real rows
  - insert_record    : insert a row into a named table
  - list_tables      : return all table names from sqlite_master
  - initialize       : MCP handshake

Security (demo-grade):
  - query_database only accepts SELECT statements (blocks DDL/DML)
  - Table name injection in insert_record is blocked by allowlist check

Run standalone:
    uvicorn gateway.sqlite_mcp_server:app --host 0.0.0.0 --port 9102

Or from the project root:
    python -m uvicorn gateway.sqlite_mcp_server:app --port 9102
"""
from __future__ import annotations

import os
import re
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Database path
# ---------------------------------------------------------------------------

DB_PATH = os.environ.get("MCP_DB_PATH", "/tmp/tesht_mcp_demo.db")

_ALLOWED_TABLES = {"products", "orders"}

_BLOCKED_SQL_KEYWORDS = re.compile(
    r"\b(drop|delete|update|insert|alter|create|truncate|replace|attach|detach)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

_PRODUCTS = [
    (1, "Widget Pro", 29.99, "hardware", 1),
    (2, "Laptop Stand", 49.99, "accessories", 1),
    (3, "USB-C Hub 7-Port", 39.99, "accessories", 1),
    (4, "Mechanical Keyboard", 129.99, "peripherals", 0),
    (5, "Wireless Mouse", 59.99, "peripherals", 1),
    (6, "4K Webcam", 89.99, "peripherals", 1),
    (7, "Desk Mat XL", 24.99, "accessories", 1),
    (8, "Monitor Light Bar", 34.99, "accessories", 0),
    (9, "Cable Management Kit", 14.99, "accessories", 1),
    (10, "Ergonomic Wrist Rest", 19.99, "accessories", 1),
]

_ORDERS = [
    (1, 1, 2, "shipped", "2024-01-10"),
    (2, 3, 1, "delivered", "2024-01-11"),
    (3, 5, 3, "processing", "2024-01-12"),
    (4, 2, 1, "shipped", "2024-01-13"),
    (5, 7, 5, "delivered", "2024-01-14"),
]


def _init_db(db_path: str) -> None:
    """Create tables and seed data if the database doesn't exist yet."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            category TEXT NOT NULL,
            in_stock INTEGER NOT NULL DEFAULT 1
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    # Seed only if empty
    if cur.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO products VALUES (?, ?, ?, ?, ?)", _PRODUCTS
        )
    if cur.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO orders VALUES (?, ?, ?, ?, ?)", _ORDERS
        )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Credential tracking (mirrors mock_mcp_server for the isolation demo)
# ---------------------------------------------------------------------------

_credentials_received: list[dict[str, Any]] = []


def _track_credentials(headers: dict[str, str]) -> None:
    tracked: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "headers_received": {},
    }
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower.startswith("x-") or k_lower in ("authorization", "x-api-key"):
            tracked["headers_received"][k] = v[:20] + "…" if len(v) > 20 else v
    _credentials_received.append(tracked)


# ---------------------------------------------------------------------------
# SQLite query helpers
# ---------------------------------------------------------------------------

def _run_select(sql: str) -> dict[str, Any]:
    """Execute a SELECT query and return rows + column names."""
    if _BLOCKED_SQL_KEYWORDS.search(sql):
        return {"error": "Only SELECT queries are allowed"}
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute(sql)
        rows = [dict(r) for r in cur.fetchall()]
        columns = [desc[0] for desc in cur.description] if cur.description else []
        return {"columns": columns, "rows": rows, "row_count": len(rows)}
    except sqlite3.Error as exc:
        return {"error": str(exc)}
    finally:
        conn.close()


def _run_insert(table: str, data: dict[str, Any]) -> dict[str, Any]:
    if table not in _ALLOWED_TABLES:
        return {"error": f"Table '{table}' not allowed. Must be one of: {sorted(_ALLOWED_TABLES)}"}
    cols = list(data.keys())
    placeholders = ", ".join("?" for _ in cols)
    col_list = ", ".join(cols)
    values = [data[c] for c in cols]
    sql = f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})"
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(sql)
        new_id = cur.lastrowid
        conn.commit()
        cur.execute(f"SELECT * FROM {table} WHERE id = ?", (new_id,))
        conn.row_factory = sqlite3.Row
        cur2 = conn.cursor()
        cur2.execute(f"SELECT * FROM {table} WHERE rowid = ?", (new_id,))
        row = cur2.fetchone()
        return {
            "inserted": True,
            "table": table,
            "new_id": new_id,
            "record": dict(row) if row else data,
        }
    except sqlite3.Error as exc:
        return {"error": str(exc)}
    finally:
        conn.close()


def _list_tables() -> dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [r[0] for r in cur.fetchall()]
        table_info = {}
        for t in tables:
            cur.execute(f"SELECT COUNT(*) FROM {t}")
            table_info[t] = {"row_count": cur.fetchone()[0]}
        return {"tables": tables, "info": table_info}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# MCP tools specification
# ---------------------------------------------------------------------------

_TOOLS = [
    {
        "name": "query_database",
        "description": "Execute a read-only SQL SELECT query against the product/order database",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "SQL SELECT query to execute",
                }
            },
            "required": ["sql"],
        },
    },
    {
        "name": "insert_record",
        "description": "Insert a new record into a database table",
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Table name (products or orders)",
                    "enum": ["products", "orders"],
                },
                "data": {
                    "type": "object",
                    "description": "Record fields to insert",
                },
            },
            "required": ["table", "data"],
        },
    },
    {
        "name": "list_tables",
        "description": "List all available database tables with row counts",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(application: FastAPI):
    _init_db(DB_PATH)
    yield


app = FastAPI(title="Tesht SQLite MCP Server", version="0.1.0", lifespan=lifespan)

if os.getenv("TESHT_CORS_ENABLED", "").lower() in ("1", "true", "yes"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.post("/mcp")
async def mcp_endpoint(request: Request) -> JSONResponse:
    _track_credentials(dict(request.headers))
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status_code=400,
        )

    req_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params", {})

    # ── initialize ────────────────────────────────────────────────────
    if method == "initialize":
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "Tesht SQLite MCP",
                    "version": "0.1.0",
                    "description": "Real SQLite database with product catalog and order data",
                },
                "capabilities": {"tools": {"listChanged": False}},
            },
        })

    # ── tools/list ───────────────────────────────────────────────────
    if method == "tools/list":
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": _TOOLS},
        })

    # ── tools/call ───────────────────────────────────────────────────
    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name == "query_database":
            sql = arguments.get("sql", "")
            if not sql:
                result_data = {"error": "sql argument is required"}
            else:
                result_data = _run_select(sql)

        elif tool_name == "insert_record":
            table = arguments.get("table", "")
            data = arguments.get("data", {})
            result_data = _run_insert(table, data)

        elif tool_name == "list_tables":
            result_data = _list_tables()

        else:
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
            })

        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": str(result_data)}],
                "isError": "error" in result_data,
                "_data": result_data,
            },
        })

    # ── notifications/initialized (no response needed) ───────────────
    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})

    return JSONResponse({
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    })


@app.get("/health")
async def health() -> dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM products")
        product_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM orders")
        order_count = cur.fetchone()[0]
    finally:
        conn.close()
    return {
        "status": "healthy",
        "db_path": DB_PATH,
        "tables": {
            "products": product_count,
            "orders": order_count,
        },
    }


@app.get("/credentials-received")
async def credentials_received() -> dict[str, Any]:
    """Return all credentials/headers received — used for the isolation demo."""
    return {
        "count": len(_credentials_received),
        "credentials": _credentials_received[-20:],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9102)
