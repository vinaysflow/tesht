"""Tests for gateway.scope."""
from gateway.config import UpstreamServer
from gateway.scope import ScopeChecker


def _make_checker():
    servers = {
        "db": UpstreamServer(
            name="db", url="http://localhost:9100/mcp",
            tool_scope_mapping={
                "query_database": "read_data",
                "insert_record": "write_data",
                "delete_record": "admin",
            },
        ),
    }
    return ScopeChecker(servers)


class TestScopeChecker:
    def test_tool_in_scope_allowed(self):
        c = _make_checker()
        r = c.check("db", "query_database", {"actions": ["read_data", "write_data"]})
        assert r.allowed is True
        assert r.required_action == "read_data"
        assert r.reason == "allowed"

    def test_tool_not_in_scope_blocked(self):
        c = _make_checker()
        r = c.check("db", "delete_record", {"actions": ["read_data"]})
        assert r.allowed is False
        assert r.required_action == "admin"
        assert "admin" in r.reason
        assert "not in delegation scope" in r.reason

    def test_unknown_tool_blocked(self):
        c = _make_checker()
        r = c.check("db", "drop_table", {"actions": ["read_data"]})
        assert r.allowed is False
        assert r.required_action is None
        assert "not registered" in r.reason

    def test_unknown_server(self):
        c = _make_checker()
        r = c.check("nonexistent", "query_database", {"actions": ["read_data"]})
        assert r.allowed is False

    def test_empty_scope_actions_blocked(self):
        c = _make_checker()
        r = c.check("db", "query_database", {"actions": []})
        assert r.allowed is False

    def test_scope_with_multi_action(self):
        c = _make_checker()
        scope = {"actions": ["read_data", "write_data", "admin"]}
        assert c.check("db", "query_database", scope).allowed
        assert c.check("db", "insert_record", scope).allowed
        assert c.check("db", "delete_record", scope).allowed

    def test_get_required_action(self):
        c = _make_checker()
        assert c.get_required_action("db", "query_database") == "read_data"
        assert c.get_required_action("db", "unknown_tool") is None
        assert c.get_required_action("nope", "query_database") is None
