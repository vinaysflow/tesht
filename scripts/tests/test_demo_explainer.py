"""
Tests for scripts/demo_explainer.py

Each test captures stdout via capsys and verifies that key strings are
present in the output.  No real JWTs are verified — tests use known-good
fixtures or minimal synthetic data.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

# Ensure scripts/ is importable
SCRIPTS_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(PROJECT_ROOT / "sdk" / "python"))
sys.path.insert(0, str(PROJECT_ROOT))

from demo_explainer import (
    decode_and_display_vp,
    display_credential_isolation,
    display_delegation_chain,
    display_trust_breakdown,
    display_trust_timeline,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_jwt(header: dict, payload: dict) -> str:
    """Construct a minimal unsigned JWT for testing (no signature check)."""
    def _b64(d: dict) -> str:
        raw = json.dumps(d).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_b64(header)}.{_b64(payload)}.fakesignature"


def _make_vc_jwt(ctype: str, issuer: str, subject: str, claims: dict) -> str:
    header = {"alg": "EdDSA", "typ": "JWT", "kid": f"{issuer}#key-1"}
    payload = {
        "iss": issuer,
        "sub": subject,
        "iat": 1710000000,
        "exp": 1710003600,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", ctype],
            "credentialSubject": {"id": subject, **claims},
        },
    }
    return _make_jwt(header, payload)


def _make_vp_jwt(holder: str, audience: str, vc_tokens: list[str]) -> str:
    header = {"alg": "EdDSA", "typ": "JWT"}
    payload = {
        "iss": holder,
        "aud": audience,
        "exp": 1710003900,
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation", "BlendedIdentityPresentation"],
            "verifiableCredential": vc_tokens,
        },
    }
    return _make_jwt(header, payload)


# ── Test 1: decode_and_display_vp ─────────────────────────────────────────────

class TestDecodeAndDisplayVp:
    def test_shows_holder_and_credentials(self, capsys):
        delegation_vc = _make_vc_jwt(
            "DelegationCredential",
            "did:key:zAlice",
            "did:key:zBot",
            {"delegatedBy": "did:key:zAlice", "delegationScope": {"actions": ["purchase"]}},
        )
        org_vc = _make_vc_jwt(
            "OrganizationalRoleCredential",
            "did:key:zIdP",
            "did:key:zAlice",
            {"name": "Alice Johnson", "email": "alice@acme.com", "organization": "Acme Corp"},
        )
        agent_vc = _make_vc_jwt(
            "AgentCredential",
            "did:key:zBot",
            "did:key:zBot",
            {"agentName": "ShoppingBot"},
        )
        vp = _make_vp_jwt("did:key:zBot", "did:key:zGW", [delegation_vc, org_vc, agent_vc])

        decode_and_display_vp(vp)
        captured = capsys.readouterr().out

        assert "VP-JWT DECODED" in captured
        assert "did:key:zBot" in captured
        assert "DelegationCredential" in captured
        assert "OrganizationalRoleCredential" in captured
        assert "AgentCredential" in captured
        assert "Alice Johnson" in captured

    def test_empty_vp_jwt_does_not_crash(self, capsys):
        decode_and_display_vp("")
        captured = capsys.readouterr().out
        assert captured == ""

    def test_malformed_jwt_does_not_crash(self, capsys):
        decode_and_display_vp("not.a.valid.jwt.string.at.all")
        # Should either print nothing or partial output — no exception
        capsys.readouterr()


# ── Test 2: display_trust_breakdown ───────────────────────────────────────────

class TestDisplayTrustBreakdown:
    def test_zero_penalty_shows_no_penalties(self, capsys):
        factors = {
            "credential_validity": 25,
            "delegation_depth": 20,
            "issuer_reputation": 20,
            "agent_history": 15,
            "behavioral_penalty": 0,
        }
        display_trust_breakdown(factors, score=80, decision="allow", tool_name="query_db")
        captured = capsys.readouterr().out

        assert "TRUST SCORE BREAKDOWN" in captured
        assert "80" in captured
        assert "ALLOW" in captured
        assert "No penalties" in captured

    def test_with_scope_penalty_shows_breakdown(self, capsys):
        factors = {
            "credential_validity": 25,
            "delegation_depth": 20,
            "issuer_reputation": 20,
            "agent_history": 15,
            "behavioral_penalty": 15,
            "tool_pattern_penalty": 0,
            "velocity_penalty": 0,
            "scope_probe_penalty": 15,
            "scope_violations": 2,
            "novel_tools": [],
            "requests_last_60s": 5,
        }
        display_trust_breakdown(factors, score=65, decision="step_up")
        captured = capsys.readouterr().out

        assert "STEP-UP" in captured
        assert "65" in captured
        assert "15" in captured  # penalty value
        assert "Scope Probing" in captured

    def test_missing_factors_does_not_crash(self, capsys):
        # Empty factors dict returns early without crashing
        display_trust_breakdown({}, score=0, decision="block")
        captured = capsys.readouterr().out
        # Empty factors → no output, but no exception either
        assert captured == "" or "BLOCK" in captured

    def test_max_penalty_shows_critical(self, capsys):
        factors = {
            "credential_validity": 25,
            "delegation_depth": 25,
            "issuer_reputation": 20,
            "agent_history": 15,
            "behavioral_penalty": 85,
            "tool_pattern_penalty": 15,
            "velocity_penalty": 20,
            "scope_probe_penalty": 25,
            "scope_violations": 5,
            "novel_tools": ["delete_all", "drop_table"],
            "requests_last_60s": 80,
        }
        display_trust_breakdown(factors, score=0, decision="block")
        captured = capsys.readouterr().out
        assert "BLOCK" in captured


# ── Test 3: display_delegation_chain ─────────────────────────────────────────

class TestDisplayDelegationChain:
    def test_single_link_chain(self, capsys):
        chain = [{
            "delegator": "did:key:zAlice",
            "delegate": "did:key:zBot",
            "scope": {"actions": ["purchase", "browse"], "max_amount": 500},
            "depth": 1,
            "max_depth": 2,
        }]
        effective_scope = {"actions": ["purchase", "browse"], "max_amount": 500, "currency": "USD"}
        delegator_claims = {
            "name": "Alice Johnson",
            "email": "alice@acmecorp.com",
            "organization": "Acme Corp",
            "role": "Senior Buyer",
        }
        display_delegation_chain(chain, effective_scope, delegator_claims, "did:key:zBot")
        captured = capsys.readouterr().out

        assert "DELEGATION CHAIN" in captured
        assert "Alice Johnson" in captured
        assert "ShoppingBot" in captured
        assert "purchase" in captured
        assert "Scope narrowing" in captured
        assert "Chain signature" in captured

    def test_empty_chain_does_not_crash(self, capsys):
        display_delegation_chain([], {}, {}, None)
        captured = capsys.readouterr().out
        assert "DELEGATION CHAIN" in captured


# ── Test 4: display_credential_isolation ─────────────────────────────────────

class TestDisplayCredentialIsolation:
    def test_shows_both_sides(self, capsys):
        vp = _make_vp_jwt("did:key:zBot", "did:key:zGW", [])
        server_entry = {
            "auth_header": "X-API-Key secret",
            "api_key_present": True,
            "api_key_value": "secret-key-12***",
            "agent_did": "did:key:zBot",
            "delegator": "did:key:zAlice",
        }
        display_credential_isolation(vp, server_entry)
        captured = capsys.readouterr().out

        assert "CREDENTIAL ISOLATION" in captured
        assert "AGENT SIDE" in captured
        assert "MCP SERVER SIDE" in captured
        assert "VERIFIED" in captured

    def test_none_server_entry_does_not_crash(self, capsys):
        vp = _make_vp_jwt("did:key:zBot", "did:key:zGW", [])
        display_credential_isolation(vp, None)
        captured = capsys.readouterr().out
        assert "CREDENTIAL ISOLATION" in captured


# ── Test 5: display_trust_timeline ────────────────────────────────────────────

class TestDisplayTrustTimeline:
    def test_empty_events_does_not_crash(self, capsys):
        display_trust_timeline([])
        captured = capsys.readouterr().out
        assert captured == ""

    def test_normal_session_events(self, capsys):
        events = [
            {"tool_name": "query_database", "trust_score": 80, "trust_decision": "allow",
             "decision": "allowed", "trust_factors": {"behavioral_penalty": 0}},
            {"tool_name": "delete_record", "trust_score": 75, "trust_decision": "allow",
             "decision": "blocked_scope", "trust_factors": {"behavioral_penalty": 5}},
            {"tool_name": "delete_record", "trust_score": 60, "trust_decision": "allow",
             "decision": "blocked_scope", "trust_factors": {"behavioral_penalty": 20}},
            {"tool_name": "query_database", "trust_score": 60, "trust_decision": "step_up",
             "decision": "step_up", "trust_factors": {"behavioral_penalty": 20}},
            {"tool_name": "query_database", "trust_score": 80, "trust_decision": "allow",
             "decision": "allowed", "trust_factors": {"behavioral_penalty": 0}},
        ]
        display_trust_timeline(events)
        captured = capsys.readouterr().out

        assert "TRUST SCORE TIMELINE" in captured
        assert "ALLOW threshold" in captured
        assert "STEP-UP threshold" in captured
        # Check score values appear
        assert "80" in captured
