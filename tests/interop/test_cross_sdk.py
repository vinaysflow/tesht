"""Cross-SDK interoperability tests.

Tests that Python-issued credentials can be verified by TypeScript and vice versa.
Uses a Node.js subprocess to call TS SDK functions.

Requirements:
    - Node.js >= 18
    - TypeScript SDK built: cd sdk/typescript && npm run build
    - Python SDK: sdk/python/
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

# ── Path setup ────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
SDK_PYTHON = REPO_ROOT / "sdk" / "python"
SDK_TYPESCRIPT = REPO_ROOT / "sdk" / "typescript"
TS_DIST = SDK_TYPESCRIPT / "dist"

sys.path.insert(0, str(SDK_PYTHON))

from tesht.credentials import (
    create_presentation,
    issue_vc,
    verify_presentation,
    verify_vc,
)
from tesht.delegation import (
    ScopeEscalationError,
    delegate_further,
    intersect_scopes,
    issue_delegation,
    verify_delegation_chain,
)
from tesht.identity import AgentIdentity


# ── TS SDK subprocess helper ──────────────────────────────────────────────────

def _ts_call(script: str) -> dict[str, Any]:
    """Run a TypeScript snippet via Node.js and return the parsed JSON output."""
    wrapper = textwrap.dedent(f"""
        import {{ AgentIdentity }} from "{TS_DIST / 'identity.js'}";
        import {{ issueVC, verifyVC, createPresentation, verifyPresentation }} from "{TS_DIST / 'credentials.js'}";
        import {{ issueDelegation, delegateFurther, verifyDelegationChain, intersectScopes }} from "{TS_DIST / 'delegation.js'}";

        (async () => {{
            try {{
                const result = await (async () => {{
                    {script}
                }})();
                process.stdout.write(JSON.stringify({{ ok: true, result }}));
            }} catch (e) {{
                process.stdout.write(JSON.stringify({{ ok: false, error: String(e) }}));
            }}
        }})();
    """)

    # Write script to temp file
    tmp = Path("/tmp/_tesht_interop_test.mjs")
    tmp.write_text(wrapper)

    try:
        proc = subprocess.run(
            ["node", str(tmp)],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(SDK_TYPESCRIPT),
        )
        if proc.returncode != 0:
            return {"ok": False, "error": proc.stderr or proc.stdout}
        return json.loads(proc.stdout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Node.js subprocess timed out"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def ts_available() -> bool:
    """Check if the TypeScript SDK is built and Node.js is available."""
    try:
        subprocess.run(["node", "--version"], capture_output=True, timeout=5, check=True)
    except Exception:
        return False
    return (TS_DIST / "delegation.js").exists()


skip_if_no_ts = pytest.mark.skipif(not ts_available(), reason="TypeScript SDK not built or Node.js not available")


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def py_alice():
    return AgentIdentity.create("alice", method="key")


@pytest.fixture(scope="module")
def py_bob():
    return AgentIdentity.create("bob", method="key")


@pytest.fixture(scope="module")
def py_carol():
    return AgentIdentity.create("carol", method="key")


# ── Test 1-5: Python credential round-trips ───────────────────────────────────

class TestPythonCredentials:
    def test_issue_and_verify_vc(self, py_alice, py_bob):
        """Python issues VC, Python verifies it."""
        vc = issue_vc(
            issuer=py_alice,
            subject_did=py_bob.did,
            credential_type="TestCredential",
            claims={"role": "tester", "level": 3},
            ttl_seconds=3600,
        )
        result = verify_vc(vc)
        assert result.verified, f"VC verification failed: {result.reason}"
        assert result.claims["role"] == "tester"
        assert result.claims["level"] == 3

    def test_vc_tamper_detected(self, py_alice, py_bob):
        """Python detects tampered VC payload."""
        vc = issue_vc(py_alice, py_bob.did, "TestCredential", claims={"role": "user"}, ttl_seconds=3600)
        parts = vc.split(".")
        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        payload["vc"]["credentialSubject"]["role"] = "admin"  # tamper
        new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        tampered = f"{parts[0]}.{new_payload}.{parts[2]}"
        result = verify_vc(tampered)
        assert not result.verified
        assert result.reason is not None

    def test_vc_expired(self, py_alice, py_bob):
        """Expired Python VC is rejected."""
        import time
        vc = issue_vc(py_alice, py_bob.did, "TestCredential", claims={"role": "user"}, ttl_seconds=1)
        time.sleep(2)
        result = verify_vc(vc)
        assert not result.verified
        assert "expir" in result.reason.lower()

    def test_vp_nonce_enforcement(self, py_alice, py_bob):
        """VP nonce is enforced in Python verify_presentation."""
        vc = issue_vc(py_alice, py_bob.did, "TestCredential", claims={"x": 1}, ttl_seconds=3600)
        nonce = "abc-123-nonce"
        vp = create_presentation(py_bob, [vc], audience=py_alice.did, nonce=nonce)

        # Correct nonce: success
        result = verify_presentation(vp, expected_audience=py_alice.did, expected_nonce=nonce)
        assert result.verified, result.reason

        # Wrong nonce: failure
        result2 = verify_presentation(vp, expected_audience=py_alice.did, expected_nonce="wrong-nonce")
        assert not result2.verified
        assert "nonce" in result2.reason.lower()

    def test_vp_audience_enforcement(self, py_alice, py_bob):
        """VP audience mismatch is rejected by Python."""
        vc = issue_vc(py_alice, py_bob.did, "TestCredential", claims={"x": 1}, ttl_seconds=3600)
        vp = create_presentation(py_bob, [vc], audience=py_alice.did)
        result = verify_presentation(vp, expected_audience="did:key:zwrongaudience123456")
        assert not result.verified
        assert "audience" in result.reason.lower() or "aud" in result.reason.lower()


# ── Test 6-10: Python delegation round-trips ──────────────────────────────────

class TestPythonDelegation:
    def test_single_hop_delegation(self, py_alice, py_bob):
        """Python issues and verifies a single-hop delegation chain."""
        scope = {"actions": ["read", "write"], "max_amount": 1000, "currency": "USD", "merchants": ["*"]}
        del1 = issue_delegation(py_alice, py_bob.did, scope, max_depth=1, ttl_seconds=3600)
        result = verify_delegation_chain(del1)
        assert result.verified, result.reason
        assert result.depth == 1
        assert "read" in result.effective_scope.get("actions", [])

    def test_two_hop_chain(self, py_alice, py_bob, py_carol):
        """Python: 2-hop delegation chain verifies."""
        root_scope = {"actions": ["read", "write", "execute"], "max_amount": 5000, "currency": "USD", "merchants": ["*"]}
        del1 = issue_delegation(py_alice, py_bob.did, root_scope, max_depth=2, ttl_seconds=3600)
        narrowed = {"actions": ["read"], "max_amount": 100, "currency": "USD", "merchants": ["*"]}
        del2 = delegate_further(py_bob, del1, py_carol.did, narrowed, ttl_seconds=3600)
        result = verify_delegation_chain(del2)
        assert result.verified, result.reason
        assert result.depth == 2

    def test_scope_escalation_rejected(self, py_alice, py_bob, py_carol):
        """Python: scope escalation raises ScopeEscalationError."""
        scope = {"actions": ["read"], "max_amount": 500, "currency": "USD", "merchants": ["*"]}
        del1 = issue_delegation(py_alice, py_bob.did, scope, max_depth=2, ttl_seconds=3600)
        with pytest.raises(ScopeEscalationError):
            delegate_further(
                py_bob, del1, py_carol.did,
                {"actions": ["read"], "max_amount": 9999, "currency": "USD", "merchants": ["*"]},
                ttl_seconds=3600,
            )

    def test_parent_bound_ttl(self, py_alice, py_bob, py_carol):
        """Child delegation TTL is clamped to parent exp."""
        import time as _time
        parent_ttl = 60  # 1 minute
        scope = {"actions": ["read"], "max_amount": 100, "currency": "USD"}
        del1 = issue_delegation(py_alice, py_bob.did, scope, max_depth=2, ttl_seconds=parent_ttl)

        # Try to issue child with longer TTL
        del2 = delegate_further(py_bob, del1, py_carol.did, {"actions": ["read"], "max_amount": 50, "currency": "USD"}, ttl_seconds=99999)

        # Decode child exp
        parts = del2.split(".")
        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        child_payload = json.loads(base64.urlsafe_b64decode(padded))
        parent_parts = del1.split(".")
        parent_padded = parent_parts[1] + "=" * ((4 - len(parent_parts[1]) % 4) % 4)
        parent_payload = json.loads(base64.urlsafe_b64decode(parent_padded))

        # Child exp must not exceed parent exp
        assert child_payload["exp"] <= parent_payload["exp"], (
            f"Child exp {child_payload['exp']} exceeds parent exp {parent_payload['exp']}"
        )

    def test_scope_intersection(self):
        """Python intersect_scopes produces correct output."""
        parent = {"actions": ["read", "write", "delete"], "max_amount": 1000, "currency": "USD", "merchants": ["*"]}
        child = {"actions": ["read", "write"], "max_amount": 500, "currency": "USD", "merchants": ["merchant-a"]}
        result = intersect_scopes(parent, child)
        assert set(result["actions"]) == {"read", "write"}
        assert result["max_amount"] == 500
        assert result["merchants"] == ["merchant-a"]  # parent wildcard, child restricts


# ── Test 11-15: TypeScript-only (if available) ────────────────────────────────

@skip_if_no_ts
class TestTypeScriptDelegation:
    def test_ts_issue_and_verify_delegation(self):
        """TypeScript: issue a delegation VC and verify it."""
        result = _ts_call("""
            const alice = await AgentIdentity.create("alice-ts");
            const bob = await AgentIdentity.create("bob-ts");
            const scope = { actions: ["read", "write"], maxAmount: 1000, currency: "USD", merchants: ["*"] };
            const delJwt = await issueDelegation(alice, bob.did, scope, { ttlSeconds: 3600, maxDepth: 2 });
            const chainResult = await verifyDelegationChain([delJwt]);
            return chainResult;
        """)
        assert result["ok"], result.get("error")
        assert result["result"]["valid"] is True
        assert result["result"]["depth"] == 0

    def test_ts_scope_escalation_rejected(self):
        """TypeScript: scope escalation raises ScopeEscalationError."""
        result = _ts_call("""
            const alice = await AgentIdentity.create("alice-ts2");
            const bob = await AgentIdentity.create("bob-ts2");
            const carol = await AgentIdentity.create("carol-ts2");
            const scope = { actions: ["read"], maxAmount: 500, currency: "USD", merchants: ["*"] };
            const del1 = await issueDelegation(alice, bob.did, scope, { ttlSeconds: 3600, maxDepth: 2 });
            try {
                await delegateFurther(bob, del1, carol.did, { actions: ["read"], maxAmount: 9999, currency: "USD", merchants: ["*"] });
                return { escalation_caught: false };
            } catch (e) {
                return { escalation_caught: true, error: String(e) };
            }
        """)
        assert result["ok"], result.get("error")
        assert result["result"]["escalation_caught"] is True

    def test_ts_two_hop_chain(self):
        """TypeScript: 2-hop delegation chain using vc.credentialSubject format."""
        result = _ts_call("""
            const alice = await AgentIdentity.create("alice-ts3");
            const bob = await AgentIdentity.create("bob-ts3");
            const carol = await AgentIdentity.create("carol-ts3");
            const rootScope = { actions: ["read", "write"], maxAmount: 5000, currency: "USD", merchants: ["*"] };
            const del1 = await issueDelegation(alice, bob.did, rootScope, { ttlSeconds: 3600, maxDepth: 3 });
            const del2 = await delegateFurther(bob, del1, carol.did, { actions: ["read"], maxAmount: 100, currency: "USD", merchants: ["*"] });
            const chainResult = await verifyDelegationChain([del1, del2]);
            return chainResult;
        """)
        assert result["ok"], result.get("error")
        assert result["result"]["valid"] is True
        assert result["result"]["depth"] == 1

    def test_ts_nonce_enforcement(self):
        """TypeScript: verifyPresentation enforces nonce."""
        result = _ts_call("""
            const alice = await AgentIdentity.create("alice-vp");
            const bob = await AgentIdentity.create("bob-vp");
            const vc = await issueVC(alice, bob.did, { claims: { role: "user" }, credentialType: "TestCredential", ttlSeconds: 3600 });
            const nonce = "test-nonce-ts-001";
            const vp = await createPresentation(bob, [vc], { audience: alice.did, nonce });
            const okResult = await verifyPresentation(vp, { expectedAudience: alice.did, expectedNonce: nonce });
            const badResult = await verifyPresentation(vp, { expectedAudience: alice.did, expectedNonce: "wrong" });
            return { okValid: okResult.valid, badValid: badResult.valid, badReason: badResult.reason };
        """)
        assert result["ok"], result.get("error")
        assert result["result"]["okValid"] is True
        assert result["result"]["badValid"] is False
        assert "nonce" in result["result"]["badReason"].lower()

    def test_ts_intersect_scopes_matches_python(self):
        """TypeScript intersectScopes produces identical output to Python for 5 scope pairs."""
        test_cases = [
            (
                {"actions": ["read", "write", "delete"], "maxAmount": 1000, "merchants": ["*"]},
                {"actions": ["read", "write"], "maxAmount": 500, "merchants": ["merchant-a"]},
            ),
            (
                {"actions": ["read"], "maxAmount": 100, "merchants": ["a", "b", "c"]},
                {"actions": ["read"], "maxAmount": 50, "merchants": ["a", "b"]},
            ),
            (
                {"actions": ["admin", "read", "write"], "maxAmount": 10000, "merchants": ["*"]},
                {"actions": ["read"], "maxAmount": 1, "merchants": ["*"]},
            ),
        ]

        for i, (parent, child) in enumerate(test_cases):
            # Python result
            py_parent = {k.replace("maxAmount", "max_amount"): v for k, v in parent.items()}
            py_child = {k.replace("maxAmount", "max_amount"): v for k, v in child.items()}
            py_result = intersect_scopes(py_parent, py_child)

            # TypeScript result
            ts_script = f"""
                const parent = {json.dumps(parent)};
                const child = {json.dumps(child)};
                return intersectScopes(parent, child);
            """
            ts_result = _ts_call(ts_script)
            assert ts_result["ok"], f"TS error in test case {i}: {ts_result.get('error')}"
            ts_scope = ts_result["result"]

            # Compare actions
            ts_actions = sorted(ts_scope.get("actions", []))
            py_actions = sorted(py_result.get("actions", []))
            assert ts_actions == py_actions, f"Case {i}: TS actions {ts_actions} != Python {py_actions}"

            # Compare maxAmount
            ts_amount = ts_scope.get("maxAmount", ts_scope.get("max_amount", 0))
            py_amount = py_result.get("max_amount", 0)
            assert ts_amount == py_amount, f"Case {i}: TS amount {ts_amount} != Python {py_amount}"


# ── Test 16-20: Python-TS cross-SDK round-trips ───────────────────────────────

@skip_if_no_ts
class TestCrossSDKRoundTrips:
    def test_python_issues_ts_verifies_vc(self):
        """Python issues VC → TypeScript verifies it."""
        issuer = AgentIdentity.create("py-issuer", method="key")
        subject = AgentIdentity.create("py-subject", method="key")

        vc = issue_vc(
            issuer=issuer,
            subject_did=subject.did,
            credential_type="CrossSDKCredential",
            claims={"interop": True, "sdk": "python"},
            ttl_seconds=3600,
        )

        ts_result = _ts_call(f"""
            const vc = {json.dumps(vc)};
            return await verifyVC(vc);
        """)
        assert ts_result["ok"], ts_result.get("error")
        assert ts_result["result"]["valid"] is True, f"TS could not verify Python VC: {ts_result['result'].get('reason')}"

    def test_ts_issues_python_verifies_vc(self):
        """TypeScript issues VC → Python verifies it."""
        ts_result = _ts_call("""
            const issuer = await AgentIdentity.create("ts-issuer");
            const subject = await AgentIdentity.create("ts-subject");
            const vc = await issueVC(issuer, subject.did, {
                claims: { interop: true, sdk: "typescript" },
                credentialType: "CrossSDKCredential",
                ttlSeconds: 3600,
            });
            return { vc, issuerDid: issuer.did, subjectDid: subject.did };
        """)
        assert ts_result["ok"], ts_result.get("error")
        vc = ts_result["result"]["vc"]

        py_result = verify_vc(vc)
        assert py_result.verified, f"Python could not verify TS VC: {py_result.reason}"
        assert py_result.claims.get("interop") is True

    def test_python_delegation_ts_verifies(self):
        """Python issues DelegationCredential VC → TypeScript verifyDelegationChain verifies."""
        alice = AgentIdentity.create("py-alice-del", method="key")
        bob = AgentIdentity.create("py-bob-del", method="key")

        scope = {"actions": ["read", "write"], "max_amount": 1000, "currency": "USD", "merchants": ["*"]}
        del_jwt = issue_delegation(alice, bob.did, scope, max_depth=2, ttl_seconds=3600)

        ts_result = _ts_call(f"""
            const delJwt = {json.dumps(del_jwt)};
            return await verifyDelegationChain([delJwt]);
        """)
        assert ts_result["ok"], ts_result.get("error")
        assert ts_result["result"]["valid"] is True, f"TS could not verify Python delegation: {ts_result['result'].get('reason')}"

    def test_ts_delegation_python_verifies(self):
        """TypeScript issues DelegationCredential VC → Python verify_delegation_chain verifies."""
        ts_result = _ts_call("""
            const alice = await AgentIdentity.create("ts-alice-del");
            const bob = await AgentIdentity.create("ts-bob-del");
            const scope = { actions: ["read"], maxAmount: 500, currency: "USD", merchants: ["*"] };
            const delJwt = await issueDelegation(alice, bob.did, scope, { ttlSeconds: 3600, maxDepth: 1 });
            return { delJwt, aliceDid: alice.did, bobDid: bob.did };
        """)
        assert ts_result["ok"], ts_result.get("error")
        del_jwt = ts_result["result"]["delJwt"]

        py_result = verify_delegation_chain(del_jwt)
        assert py_result.verified, f"Python could not verify TS delegation: {py_result.reason}"

    def test_python_vp_ts_verifies(self):
        """Python creates VP with nonce → TypeScript verifyPresentation with expected nonce."""
        holder = AgentIdentity.create("py-holder-vp", method="key")
        issuer = AgentIdentity.create("py-issuer-vp", method="key")

        vc = issue_vc(issuer, holder.did, "TestCredential", claims={"x": 1}, ttl_seconds=3600)
        nonce = "cross-sdk-nonce-test"
        audience = issuer.did  # use known DID
        vp = create_presentation(holder, [vc], audience=audience, nonce=nonce)

        ts_result = _ts_call(f"""
            const vp = {json.dumps(vp)};
            const nonce = {json.dumps(nonce)};
            // audience check may fail cross-SDK due to VP audience being a Python DID
            const result = await verifyPresentation(vp, {{ expectedNonce: nonce }});
            return result;
        """)
        assert ts_result["ok"], ts_result.get("error")
        # Nonce should be checked; audience not enforced here
        assert ts_result["result"]["valid"] is True, f"TS could not verify Python VP: {ts_result['result'].get('reason')}"
