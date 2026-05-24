"""Tests for gateway.jsonrpc."""
import json

import pytest

from gateway.jsonrpc import (
    JSONRPCRequest,
    build_jsonrpc_error,
    extract_tool_name,
    is_tool_call,
    parse_jsonrpc,
)


class TestParseJsonrpc:
    def test_valid_tools_call(self):
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "query_database"},
        }).encode()
        req = parse_jsonrpc(body)
        assert req.method == "tools/call"
        assert req.params["name"] == "query_database"
        assert req.id == 1

    def test_valid_tools_list(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).encode()
        req = parse_jsonrpc(body)
        assert req.method == "tools/list"
        assert req.params == {}

    def test_missing_jsonrpc_version(self):
        body = json.dumps({"id": 1, "method": "tools/list"}).encode()
        with pytest.raises(ValueError, match="Unsupported jsonrpc version"):
            parse_jsonrpc(body)

    def test_missing_method(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 1}).encode()
        with pytest.raises(ValueError, match="Missing or invalid 'method'"):
            parse_jsonrpc(body)

    def test_invalid_json(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_jsonrpc(b"not json")

    def test_non_object_body(self):
        with pytest.raises(ValueError, match="must be an object"):
            parse_jsonrpc(b"[1, 2, 3]")

    def test_null_id_allowed(self):
        body = json.dumps({"jsonrpc": "2.0", "id": None, "method": "initialize"}).encode()
        req = parse_jsonrpc(body)
        assert req.id is None


class TestExtractToolName:
    def test_tools_call(self):
        req = JSONRPCRequest(id=1, method="tools/call", params={"name": "my_tool"})
        assert extract_tool_name(req) == "my_tool"

    def test_resources_read(self):
        req = JSONRPCRequest(id=1, method="resources/read", params={"uri": "file:///x"})
        assert extract_tool_name(req) == "file:///x"

    def test_tools_list_returns_none(self):
        req = JSONRPCRequest(id=1, method="tools/list")
        assert extract_tool_name(req) is None

    def test_initialize_returns_none(self):
        req = JSONRPCRequest(id=1, method="initialize")
        assert extract_tool_name(req) is None


class TestIsToolCall:
    def test_tools_call_true(self):
        assert is_tool_call(JSONRPCRequest(id=1, method="tools/call")) is True

    def test_resources_read_true(self):
        assert is_tool_call(JSONRPCRequest(id=1, method="resources/read")) is True

    def test_tools_list_false(self):
        assert is_tool_call(JSONRPCRequest(id=1, method="tools/list")) is False


class TestBuildJsonrpcError:
    def test_basic_error(self):
        err = build_jsonrpc_error(42, -32600, "Invalid request")
        assert err["jsonrpc"] == "2.0"
        assert err["id"] == 42
        assert err["error"]["code"] == -32600
        assert err["error"]["message"] == "Invalid request"
        assert "data" not in err["error"]

    def test_error_with_data(self):
        err = build_jsonrpc_error(1, -32001, "Auth failed", data={"detail": "expired"})
        assert err["error"]["data"]["detail"] == "expired"
