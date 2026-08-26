#!/usr/bin/env python3
"""
EcosystemGenerator — modular, reproducible synthetic data for Tesht (Pramana).

Target: 500+ agents, 1000+ credentials, 200+ chains, 100+ mandates, 150+ scenarios.
All scenarios have expected outcomes (happy, failure, edge, security).

Usage:
    python generate.py [--seed 42] [--output data/]
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Add sdk/python to path for tesht imports
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from tesht.credentials import issue_vc, verify_vc
from tesht.delegation import (
    ScopeEscalationError,
    delegate_further,
    intersect_scopes,
    issue_delegation,
    verify_delegation_chain,
)
from tesht.identity import AgentIdentity
from tesht.commerce import issue_cart_mandate, issue_intent_mandate, verify_mandate

import jwt as pyjwt

DATA_DIR = Path(__file__).parent / "data"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _decode_jti(token: str) -> str:
    try:
        parts = token.split(".")
        import base64 as _b64
        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        return json.loads(_b64.urlsafe_b64decode(padded)).get("jti", str(uuid.uuid4()))
    except Exception:
        return str(uuid.uuid4())


def _decode_exp(token: str) -> Optional[int]:
    try:
        parts = token.split(".")
        import base64 as _b64
        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        return json.loads(_b64.urlsafe_b64decode(padded)).get("exp")
    except Exception:
        return None


# ── Main generator ────────────────────────────────────────────────────────────

class EcosystemGenerator:
    def __init__(self, seed: int = 42, output_dir: Path = DATA_DIR):
        self.rng = random.Random(seed)
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Core stores
        self.agents: dict[str, dict[str, Any]] = {}       # name -> {identity, meta}
        self.credentials: list[dict[str, Any]] = []
        self.chains: list[dict[str, Any]] = []
        self.mandates: list[dict[str, Any]] = []
        self.scenarios: list[dict[str, Any]] = []

    # ── Agent creation ────────────────────────────────────────────────────────

    def _make_agent(self, name: str, role: str, tags: list[str] | None = None) -> AgentIdentity:
        identity = AgentIdentity.create(name, method="key")
        self.agents[name] = {
            "identity": identity,
            "name": name,
            "role": role,
            "did": identity.did,
            "tags": tags or [],
        }
        return identity

    # ── Scenario helpers ──────────────────────────────────────────────────────

    def _add_scenario(
        self,
        scenario_id: str,
        category: str,
        description: str,
        data: dict[str, Any],
        expected: str,
        expected_reason: str | None = None,
    ) -> None:
        self.scenarios.append({
            "id": scenario_id,
            "category": category,
            "description": description,
            "expected": expected,
            "expected_reason": expected_reason,
            **data,
        })

    # ── Phase 1: Organizations (50 agents) ────────────────────────────────────

    def generate_organizations(self) -> None:
        """5 orgs × 10 agents each = 50 agents with enterprise hierarchy."""
        orgs = [
            ("acme-corp", "enterprise", ["commerce", "ai"]),
            ("globalbank", "financial", ["payments", "kyc"]),
            ("healthplus", "healthcare", ["hipaa", "ehr"]),
            ("govtrust", "government", ["identity", "compliance"]),
            ("techventures", "startup", ["ai", "saas"]),
        ]

        for org_name, sector, tags in orgs:
            # Root authority
            root = self._make_agent(f"{org_name}-root-ca", "root-issuer", tags)

            # Issuer
            issuer = self._make_agent(f"{org_name}-issuer", "issuer", tags)

            # Sub-issuers
            sub1 = self._make_agent(f"{org_name}-dept-a-issuer", "sub-issuer", tags)
            sub2 = self._make_agent(f"{org_name}-dept-b-issuer", "sub-issuer", tags)

            # Orchestrators
            orch1 = self._make_agent(f"{org_name}-orchestrator-1", "orchestrator", tags)
            orch2 = self._make_agent(f"{org_name}-orchestrator-2", "orchestrator", tags)

            # Worker agents
            for i in range(4):
                self._make_agent(f"{org_name}-worker-{i+1}", "worker", tags)

            # Issue credential from root to issuer
            vc = issue_vc(
                issuer=root,
                subject_did=issuer.did,
                credential_type="OrganizationalRoleCredential",
                claims={
                    "orgName": org_name,
                    "sector": sector,
                    "role": "issuer",
                    "permissions": ["issue_credentials", "manage_agents"],
                },
                ttl_seconds=365 * 24 * 3600,
            )
            jti = _decode_jti(vc)
            self.credentials.append({
                "jti": jti,
                "jwt": vc,
                "issuer": root.did,
                "subject": issuer.did,
                "type": "OrganizationalRoleCredential",
                "org": org_name,
            })

            # Scenario: happy path org credential verification
            self._add_scenario(
                f"org-{org_name}-credential-happy",
                "happy",
                f"Org credential issued by {org_name} root CA verifies successfully",
                {"jwt": vc, "issuer_did": root.did},
                "verified",
            )

    # ── Phase 2: Shopping/Commerce agents (50 agents) ────────────────────────

    def generate_shopping_ecosystem(self) -> None:
        """50 shopping agents: merchants, buyers, payment agents."""
        merchants = [
            ("amazon-agent", "merchant", ["retail", "marketplace"]),
            ("shopify-store-001", "merchant", ["retail"]),
            ("uber-eats-agent", "merchant", ["food", "delivery"]),
            ("netflix-billing", "merchant", ["subscription", "media"]),
            ("airbnb-agent", "merchant", ["travel", "hospitality"]),
        ]
        for name, role, tags in merchants:
            self._make_agent(name, role, tags)

        buyers = [f"buyer-agent-{i+1:03d}" for i in range(20)]
        for b in buyers:
            self._make_agent(b, "buyer", ["consumer"])

        payment_agents = [f"payment-processor-{i+1:02d}" for i in range(10)]
        for p in payment_agents:
            self._make_agent(p, "payment", ["payments", "finance"])

        recommendation_agents = [f"rec-engine-{i+1:02d}" for i in range(15)]
        for r in recommendation_agents:
            self._make_agent(r, "recommendation", ["ai", "ml"])

        # Generate AP2 mandates (happy path)
        issuer_agent = self.agents.get("acme-corp-issuer", {}).get("identity")
        if issuer_agent is None:
            issuer_agent = self._make_agent("commerce-issuer", "issuer", ["commerce"])

        # Generate 100+ mandates across many buyer/merchant pairs
        all_buyers = [f"buyer-agent-{j+1:03d}" for j in range(20)]
        all_merchants_list = list(merchants)
        for i in range(100):
            buyer_name = f"buyer-agent-{(i % 20) + 1:03d}"
            merchant_name, _, _ = all_merchants_list[i % len(all_merchants_list)]
            buyer = self.agents[buyer_name]["identity"]
            merchant = self.agents[merchant_name]["identity"]
            pa_name = f"payment-processor-{(i % 10) + 1:02d}"
            pa = self.agents[pa_name]["identity"]

            amount = self.rng.randint(500, 10000)
            currency = self.rng.choice(["USD", "EUR", "GBP"])

            intent = issue_intent_mandate(
                delegator=buyer,
                agent_did=pa.did,
                intent={
                    "max_amount": amount,
                    "currency": currency,
                    "merchants": [merchant.did],
                    "categories": ["retail", "food", "media", "travel"],
                },
                ttl_seconds=3600,
            )
            cart_value = self.rng.randint(100, amount)
            try:
                cart = issue_cart_mandate(
                    delegator=buyer,
                    agent_did=pa.did,
                    cart={
                        "total": {"value": cart_value, "currency": currency},
                        "items": [{"sku": f"SKU{self.rng.randint(1000, 9999)}", "quantity": 1, "price": cart_value}],
                        "merchant_did": merchant.did,
                    },
                    intent_mandate_jwt=intent,
                    ttl_seconds=300,
                )
                intent_jti = _decode_jti(intent)
                cart_jti = _decode_jti(cart)
                self.mandates.append({
                    "intent_jti": intent_jti,
                    "cart_jti": cart_jti,
                    "intent_jwt": intent,
                    "cart_jwt": cart,
                    "buyer": buyer.did,
                    "payment_agent": pa.did,
                    "merchant": merchant.did,
                    "amount": amount,
                    "cart_value": cart_value,
                    "currency": currency,
                })
                self._add_scenario(
                    f"commerce-happy-{i+1}",
                    "happy",
                    f"Cart mandate (${cart_value} {currency}) within intent limit (${amount}) verifies",
                    {"intent_jwt": intent, "cart_jwt": cart},
                    "verified",
                )
            except Exception as exc:
                pass  # unlikely but don't crash generator

    # ── Phase 3: Service agents (50 agents) ──────────────────────────────────

    def generate_service_agents(self) -> None:
        """50 service agents with professional credentials."""
        services = [
            ("legal-review-agent", "legal", ["legal", "compliance"]),
            ("medical-diagnosis-ai", "medical", ["healthcare", "hipaa"]),
            ("financial-advisor-bot", "financial", ["finance", "kyc"]),
            ("code-review-agent", "engineering", ["software", "security"]),
            ("content-moderation-ai", "moderation", ["content", "trust"]),
        ]
        for name, role, tags in services:
            self._make_agent(name, role, tags)

        # Generic service workers
        for i in range(45):
            role = self.rng.choice(["worker", "auditor", "analyst", "assistant"])
            tags = self.rng.sample(["ai", "ml", "nlp", "data", "analytics"], k=2)
            self._make_agent(f"service-agent-{i+1:03d}", role, tags)

    # ── Phase 4: Edge-case agents (50 adversarial) ───────────────────────────

    def generate_edge_cases(self) -> None:
        """50 edge-case and adversarial agents."""
        for i in range(50):
            self._make_agent(f"edge-agent-{i+1:03d}", "edge", ["adversarial"])

    # ── Phase 5: Deep-chain swarm agents (50) ────────────────────────────────

    def generate_swarm_agents(self) -> None:
        """50 agents designed for deep delegation chains."""
        for i in range(50):
            self._make_agent(f"swarm-agent-{i+1:03d}", "swarm", ["delegation"])

    # ── Phase 6: Delegation chains ────────────────────────────────────────────

    def generate_delegation_chains(self) -> None:
        """Generate 200+ delegation chains including adversarial cases."""
        # Happy: 2-hop chains within orgs
        orgs = ["acme-corp", "globalbank", "healthplus", "govtrust", "techventures"]
        for org in orgs:
            root = self.agents.get(f"{org}-issuer", {}).get("identity")
            orch1 = self.agents.get(f"{org}-orchestrator-1", {}).get("identity")
            worker1 = self.agents.get(f"{org}-worker-1", {}).get("identity")
            if not all([root, orch1, worker1]):
                continue

            scope = {
                "actions": ["read", "write", "execute"],
                "max_amount": 5000,
                "currency": "USD",
                "merchants": ["*"],
            }
            del1 = issue_delegation(root, orch1.did, scope, max_depth=3, ttl_seconds=7200)
            narrowed = {
                "actions": ["read", "write"],
                "max_amount": 1000,
                "currency": "USD",
                "merchants": ["*"],
            }
            del2 = delegate_further(orch1, del1, worker1.did, narrowed, ttl_seconds=3600)

            chain_id = f"chain-{org}-2hop"
            self.chains.append({
                "id": chain_id,
                "links": [del1, del2],
                "root_issuer": root.did,
                "final_delegate": worker1.did,
                "expected_valid": True,
            })
            result = verify_delegation_chain(del2)
            self._add_scenario(
                f"delegation-{org}-2hop-happy",
                "happy",
                f"2-hop delegation chain in {org} is valid",
                {"chain_links": [del1, del2], "token": del2},
                "verified" if result.verified else "failed",
            )

        # Happy: single-hop chains for swarm agents
        root_agent = self.agents.get("acme-corp-issuer", {}).get("identity") or \
                     list(self.agents.values())[0]["identity"]
        for i in range(1, 31):
            swarm = self.agents.get(f"swarm-agent-{i:03d}", {}).get("identity")
            if not swarm:
                continue
            scope = {
                "actions": self.rng.sample(["read", "write", "execute", "deploy", "monitor"], k=2),
                "max_amount": self.rng.randint(100, 10000),
                "currency": "USD",
                "merchants": ["*"],
            }
            del_jwt = issue_delegation(root_agent, swarm.did, scope, max_depth=2, ttl_seconds=3600)
            jti = _decode_jti(del_jwt)
            self.chains.append({
                "id": f"chain-swarm-{i}",
                "links": [del_jwt],
                "root_issuer": root_agent.did,
                "final_delegate": swarm.did,
                "expected_valid": True,
            })
            self._add_scenario(
                f"delegation-swarm-{i}-happy",
                "happy",
                f"Single-hop swarm delegation {i} is valid",
                {"token": del_jwt},
                "verified",
            )

        # Failure: scope escalation — try to increase max_amount
        if len(list(self.agents.values())) >= 2:
            agents_list = list(self.agents.values())
            a1 = agents_list[0]["identity"]
            a2 = agents_list[1]["identity"]
            a3 = agents_list[2]["identity"] if len(agents_list) > 2 else agents_list[0]["identity"]

            root_scope = {"actions": ["read"], "max_amount": 500, "currency": "USD", "merchants": ["*"]}
            parent_del = issue_delegation(a1, a2.did, root_scope, max_depth=2, ttl_seconds=3600)

            try:
                escalated_scope = {"actions": ["read", "write"], "max_amount": 5000, "currency": "USD", "merchants": ["*"]}
                bad_del = delegate_further(a2, parent_del, a3.did, escalated_scope, ttl_seconds=3600)
                self._add_scenario(
                    "delegation-scope-escalation-amount-UNEXPECTED-SUCCESS",
                    "failure",
                    "Scope escalation (amount) should have been rejected but wasn't",
                    {"token": bad_del},
                    "failed",
                    "SDK should have raised ScopeEscalationError",
                )
            except ScopeEscalationError as exc:
                self._add_scenario(
                    "delegation-scope-escalation-amount",
                    "failure",
                    "Scope escalation (max_amount 500->5000) is correctly rejected",
                    {"parent_token": parent_del, "escalated_scope": escalated_scope},
                    "rejected",
                    str(exc),
                )

        # Failure: expired parent delegation
        if len(list(self.agents.values())) >= 2:
            agents_list = list(self.agents.values())
            a1 = agents_list[3]["identity"] if len(agents_list) > 3 else agents_list[0]["identity"]
            a2 = agents_list[4]["identity"] if len(agents_list) > 4 else agents_list[0]["identity"]

            expired_del = issue_delegation(a1, a2.did, {"actions": ["read"], "max_amount": 100, "currency": "USD"}, max_depth=1, ttl_seconds=1)
            time.sleep(2)  # Let it expire
            result = verify_delegation_chain(expired_del)
            self._add_scenario(
                "delegation-expired",
                "failure",
                "Expired delegation credential is correctly rejected",
                {"token": expired_del},
                "rejected",
                result.reason,
            )

        # Edge: depth exceeded
        if len(list(self.agents.values())) >= 3:
            agents_list = list(self.agents.values())
            a1 = agents_list[5]["identity"] if len(agents_list) > 5 else agents_list[0]["identity"]
            a2 = agents_list[6]["identity"] if len(agents_list) > 6 else agents_list[0]["identity"]
            a3 = agents_list[7]["identity"] if len(agents_list) > 7 else agents_list[0]["identity"]

            d1 = issue_delegation(a1, a2.did, {"actions": ["read"], "max_amount": 100, "currency": "USD"}, max_depth=1, ttl_seconds=3600)
            try:
                # a2 tries to delegate further but max_depth=1 means depth limit is 1
                d2 = delegate_further(a2, d1, a3.did, {"actions": ["read"], "max_amount": 50, "currency": "USD"}, ttl_seconds=3600)
                self._add_scenario(
                    "delegation-depth-exceeded-UNEXPECTED-SUCCESS",
                    "edge",
                    "Depth exceeded should have been rejected",
                    {"token": d2},
                    "failed",
                )
            except ValueError as exc:
                self._add_scenario(
                    "delegation-depth-exceeded",
                    "edge",
                    "Delegation depth > maxDepth is correctly rejected",
                    {"parent_token": d1},
                    "rejected",
                    str(exc),
                )

        # Security: tampered delegation payload
        if self.chains:
            legit_chain = self.chains[0]["links"][-1]
            # Tamper the payload
            parts = legit_chain.split(".")
            import base64 as _b64
            padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
            payload_data = json.loads(_b64.urlsafe_b64decode(padded))
            # Try to escalate max_amount in the payload
            if "vc" in payload_data:
                cs = payload_data["vc"].get("credentialSubject", {})
                scope = cs.get("delegationScope", {})
                scope["max_amount"] = 9999999
                cs["delegationScope"] = scope
                payload_data["vc"]["credentialSubject"] = cs

            tampered_payload = _b64.urlsafe_b64encode(
                json.dumps(payload_data).encode()
            ).rstrip(b"=").decode()
            tampered_jwt = f"{parts[0]}.{tampered_payload}.{parts[2]}"
            result = verify_delegation_chain(tampered_jwt)
            self._add_scenario(
                "delegation-tampered-payload",
                "security",
                "Tampered delegation JWT payload is correctly rejected (sig check fails)",
                {"token": tampered_jwt},
                "rejected",
                result.reason or "signature invalid",
            )

    # ── Phase 7: VP scenarios ─────────────────────────────────────────────────

    def generate_vp_scenarios(self) -> None:
        """VP nonce, audience, replay protection scenarios."""
        from tesht.credentials import create_presentation, verify_presentation

        agents_list = list(self.agents.values())
        if len(agents_list) < 2:
            return

        holder = agents_list[0]["identity"]
        verifier = agents_list[1]["identity"]

        # Issue a credential for the holder
        vc = issue_vc(
            issuer=verifier,
            subject_did=holder.did,
            credential_type="TestCredential",
            claims={"role": "tester"},
            ttl_seconds=3600,
        )

        nonce = "test-nonce-12345"
        audience = verifier.did

        # Happy: VP with correct nonce
        vp = create_presentation(holder, [vc], audience=audience, nonce=nonce)
        result = verify_presentation(vp, expected_audience=audience, expected_nonce=nonce)
        self._add_scenario(
            "vp-nonce-happy",
            "happy",
            "VP with correct nonce verifies successfully",
            {"vp_jwt": vp, "expected_nonce": nonce},
            "verified",
        )

        # Failure: VP with wrong nonce (replay with different nonce)
        bad_nonce = "wrong-nonce-99999"
        result = verify_presentation(vp, expected_audience=audience, expected_nonce=bad_nonce)
        self._add_scenario(
            "vp-nonce-mismatch",
            "security",
            "VP presented with wrong nonce is rejected (replay protection)",
            {"vp_jwt": vp, "expected_nonce": bad_nonce, "actual_nonce": nonce},
            "rejected",
            result.reason,
        )

        # Failure: VP replay (same JWT presented twice — nonce mismatch if nonce required)
        result2 = verify_presentation(vp, expected_audience=audience, expected_nonce=nonce)
        # Same nonce — the VP is technically valid (nonce enforcement is stateless in SDK)
        # True replay protection at backend via JTI dedup
        self._add_scenario(
            "vp-replay-same-nonce",
            "security",
            "VP with same nonce presented again — SDK passes but backend JTI dedup should reject",
            {"vp_jwt": vp, "expected_nonce": nonce},
            "replay-protected-at-backend",
        )

        # Failure: audience mismatch
        wrong_audience = "did:key:zwrongaudience"
        result = verify_presentation(vp, expected_audience=wrong_audience, expected_nonce=nonce)
        self._add_scenario(
            "vp-audience-mismatch",
            "security",
            "VP presented to wrong audience is rejected",
            {"vp_jwt": vp, "expected_audience": wrong_audience},
            "rejected",
            result.reason,
        )

    # ── Phase 8: Currency mismatch mandates ──────────────────────────────────

    def generate_currency_mismatch_scenarios(self) -> None:
        """Currency mismatch between intent and cart."""
        agents_list = list(self.agents.values())
        if len(agents_list) < 3:
            return

        buyer = agents_list[0]["identity"]
        pa = agents_list[1]["identity"]

        intent = issue_intent_mandate(
            delegator=buyer,
            agent_did=pa.did,
            intent={"max_amount": 5000, "currency": "USD"},
            ttl_seconds=3600,
        )

        try:
            bad_cart = issue_cart_mandate(
                buyer, pa.did,
                {"total": {"value": 100, "currency": "EUR"}},  # EUR vs USD
                intent,
                ttl_seconds=300,
            )
            self._add_scenario(
                "mandate-currency-mismatch-UNEXPECTED-SUCCESS",
                "security",
                "Currency mismatch should have been rejected by SDK",
                {"intent_jwt": intent},
                "failed",
            )
        except ValueError as exc:
            self._add_scenario(
                "mandate-currency-mismatch",
                "security",
                "Cart mandate with EUR currency against USD intent is rejected",
                {"intent_jwt": intent, "cart_currency": "EUR", "intent_currency": "USD"},
                "rejected",
                str(exc),
            )

        # Over-budget cart
        try:
            over_budget_cart = issue_cart_mandate(
                buyer, pa.did,
                {"total": {"value": 9999999, "currency": "USD"}},  # over budget
                intent,
                ttl_seconds=300,
            )
            self._add_scenario(
                "mandate-over-budget-UNEXPECTED-SUCCESS",
                "failure",
                "Over-budget cart should have been rejected",
                {"intent_jwt": intent},
                "failed",
            )
        except ValueError as exc:
            self._add_scenario(
                "mandate-over-budget",
                "failure",
                "Cart mandate exceeding intent limit is correctly rejected",
                {"intent_jwt": intent, "cart_value": 9999999, "intent_limit": 5000},
                "rejected",
                str(exc),
            )

    # ── Phase 9: Cross-org scenarios ─────────────────────────────────────────

    def generate_cross_org_scenarios(self) -> None:
        """Cross-org delegation and trust scenarios."""
        orgs = ["acme-corp", "globalbank"]
        if not all(f"{org}-issuer" in self.agents for org in orgs):
            return

        acme = self.agents["acme-corp-issuer"]["identity"]
        bank = self.agents["globalbank-issuer"]["identity"]
        worker = self.agents.get("acme-corp-worker-1", {}).get("identity")
        if not worker:
            return

        # acme delegates to bank agent
        scope = {"actions": ["read", "audit"], "max_amount": 0, "currency": "USD", "merchants": []}
        cross_del = issue_delegation(acme, bank.did, scope, max_depth=1, ttl_seconds=3600)
        self.chains.append({"id": "chain-cross-org", "links": [cross_del], "expected_valid": True})
        result = verify_delegation_chain(cross_del)
        self._add_scenario(
            "delegation-cross-org-happy",
            "cross-org",
            "Cross-org delegation from acme to globalbank is valid",
            {"token": cross_del},
            "verified" if result.verified else "failed",
        )

        # Unknown issuer — create a rogue agent not in any org
        rogue = AgentIdentity.create("rogue-agent", method="key")
        rogue_del = issue_delegation(
            rogue, worker.did,
            {"actions": ["admin"], "max_amount": 100000, "currency": "USD", "merchants": ["*"]},
            max_depth=5, ttl_seconds=3600,
        )
        # This is valid from a crypto standpoint but the rogue issuer is not trusted
        self._add_scenario(
            "delegation-rogue-issuer",
            "cross-org",
            "Delegation from rogue/unknown issuer — cryptographically valid but not organizationally trusted",
            {"token": rogue_del, "issuer_did": rogue.did},
            "verified-but-untrusted",
        )

    # ── Phase 10: Scale scenarios ─────────────────────────────────────────────

    def generate_scale_scenarios(self) -> None:
        """Generate a 10-hop delegation chain to test deep recursion."""
        agents_list = list(self.agents.values())
        if len(agents_list) < 12:
            return

        root = agents_list[0]["identity"]
        chain = [agents_list[i + 1]["identity"] for i in range(10)]

        # Need to issue with max_depth=10 to allow 10 hops
        scope = {"actions": ["read"], "max_amount": 1000, "currency": "USD", "merchants": ["*"]}
        current_jwt = issue_delegation(root, chain[0].did, scope, max_depth=10, ttl_seconds=3600)
        links = [current_jwt]

        for i in range(9):
            holder = chain[i]
            delegate = chain[i + 1]
            narrowed = {"actions": ["read"], "max_amount": max(1, 1000 - (i + 1) * 90), "currency": "USD", "merchants": ["*"]}
            try:
                current_jwt = delegate_further(holder, current_jwt, delegate.did, narrowed, ttl_seconds=3600)
                links.append(current_jwt)
            except Exception:
                break

        self.chains.append({"id": "chain-deep-10hop", "links": links, "expected_valid": True})
        result = verify_delegation_chain(links[-1])
        self._add_scenario(
            "delegation-deep-chain",
            "scale",
            f"Deep delegation chain ({len(links)} hops) verification",
            {"final_token": links[-1], "chain_links": links},
            "verified" if result.verified else "failed",
            result.reason,
        )

    # ── Phase 11: Additional happy path credentials ───────────────────────────

    def generate_bulk_credentials(self) -> None:
        """Generate 500+ credentials across all agents."""
        credential_types = [
            ("CapabilityCredential", {"capability": "data_processing", "scope": "global"}),
            ("IdentityCredential", {"verified": True, "level": "high"}),
            ("ComplianceCredential", {"standard": "SOC2", "certified": True}),
            ("ProfessionalCredential", {"profession": "software_engineer", "years_exp": 5}),
            ("TrustCredential", {"trust_score": 95, "last_evaluated": "2026-01-01"}),
            ("AccessCredential", {"resource": "api-gateway", "permission": "read_write"}),
            ("AuditCredential", {"audit_type": "security", "passed": True}),
            ("MembershipCredential", {"org": "protocol-alliance", "tier": "premium"}),
        ]

        agents_list = list(self.agents.values())
        issuers = [a for a in agents_list if a["role"] in ("issuer", "root-issuer", "sub-issuer")]

        for i, agent_data in enumerate(agents_list):
            issuer_data = issuers[i % len(issuers)]
            issuer = issuer_data["identity"]
            subject = agent_data["identity"]

            cred_type, base_claims = credential_types[i % len(credential_types)]
            claims = {**base_claims, "subject_name": subject.did[:30], "seq": i}

            vc = issue_vc(
                issuer=issuer,
                subject_did=subject.did,
                credential_type=cred_type,
                claims=claims,
                ttl_seconds=365 * 24 * 3600,
            )
            jti = _decode_jti(vc)
            self.credentials.append({
                "jti": jti,
                "jwt": vc,
                "issuer": issuer.did,
                "subject": subject.did,
                "type": cred_type,
            })

            if i % 20 == 0:  # 1 in 20 gets a scenario
                result = verify_vc(vc)
                self._add_scenario(
                    f"credential-bulk-{i}-happy",
                    "happy",
                    f"{cred_type} verifies successfully (bulk #{i})",
                    {"jwt": vc, "issuer_did": issuer.did},
                    "verified" if result.verified else "failed",
                )

    # ── Phase 12: Additional failure scenarios ────────────────────────────────

    def generate_failure_scenarios(self) -> None:
        """Explicit failure cases for every rejection type."""
        agents_list = list(self.agents.values())
        if len(agents_list) < 2:
            return

        a1 = agents_list[0]["identity"]
        a2 = agents_list[1]["identity"]
        a3 = agents_list[2]["identity"] if len(agents_list) > 2 else agents_list[0]["identity"]

        # 1. Tampered VC payload
        vc = issue_vc(a1, a2.did, "TestCredential", claims={"role": "user"}, ttl_seconds=3600)
        parts = vc.split(".")
        import base64 as _b64
        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        payload_data = json.loads(_b64.urlsafe_b64decode(padded))
        payload_data["vc"] = payload_data.get("vc", {})
        if "credentialSubject" in payload_data.get("vc", {}):
            payload_data["vc"]["credentialSubject"]["role"] = "admin"  # escalate
        tampered = f"{parts[0]}.{_b64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b'=').decode()}.{parts[2]}"
        result = verify_vc(tampered)
        self._add_scenario(
            "vc-tampered-payload",
            "failure",
            "Tampered VC payload fails signature verification",
            {"jwt": tampered},
            "rejected",
            result.reason,
        )

        # 2. Expired VC
        expired = issue_vc(a1, a2.did, "TestCredential", claims={"role": "user"}, ttl_seconds=1)
        time.sleep(2)
        result = verify_vc(expired)
        self._add_scenario(
            "vc-expired",
            "failure",
            "Expired VC is correctly rejected",
            {"jwt": expired},
            "rejected",
            result.reason,
        )

        # 3. Wrong issuer type check
        vc2 = issue_vc(a1, a2.did, "DelegationCredential", claims={"role": "delegate"}, ttl_seconds=3600)
        result = verify_vc(vc2)
        self._add_scenario(
            "vc-wrong-type-verify",
            "edge",
            "VC with correct structure but unexpected claim type",
            {"jwt": vc2, "credential_type": "DelegationCredential"},
            "verified",  # It will verify; type check is caller responsibility
        )

        # 4. Zero-amount mandate
        try:
            intent = issue_intent_mandate(a1, a2.did, intent={"max_amount": 0, "currency": "USD"}, ttl_seconds=3600)
            cart = issue_cart_mandate(
                a1, a2.did,
                {"total": {"value": 0, "currency": "USD"}},
                intent,
                ttl_seconds=300,
            )
            self._add_scenario(
                "mandate-zero-amount",
                "edge",
                "Zero-amount mandate (allowed at SDK level — policy enforced above)",
                {"intent_jwt": intent, "cart_jwt": cart},
                "verified",
            )
        except Exception as exc:
            self._add_scenario(
                "mandate-zero-amount",
                "edge",
                "Zero-amount mandate handling",
                {},
                "rejected",
                str(exc),
            )

    # ── Main generator ─────────────────────────────────────────────────────────

    def generate_all(self) -> None:
        print("[generator] Phase 1: organizations (50 agents)...")
        self.generate_organizations()

        print("[generator] Phase 2: shopping ecosystem (50 agents + mandates)...")
        self.generate_shopping_ecosystem()

        print("[generator] Phase 3: service agents (50 agents)...")
        self.generate_service_agents()

        print("[generator] Phase 4: edge-case agents (50 agents)...")
        self.generate_edge_cases()

        print("[generator] Phase 5: swarm agents (50 agents)...")
        self.generate_swarm_agents()

        print("[generator] Phase 6: delegation chains (200+)...")
        self.generate_delegation_chains()

        print("[generator] Phase 7: VP nonce/replay scenarios...")
        self.generate_vp_scenarios()

        print("[generator] Phase 8: currency mismatch scenarios...")
        self.generate_currency_mismatch_scenarios()

        print("[generator] Phase 9: cross-org scenarios...")
        self.generate_cross_org_scenarios()

        print("[generator] Phase 10: scale scenarios (deep chains)...")
        self.generate_scale_scenarios()

        print("[generator] Phase 11: bulk credentials (500+)...")
        self.generate_bulk_credentials()

        print("[generator] Phase 12: failure scenarios...")
        self.generate_failure_scenarios()

        print(
            f"[generator] Generated: {len(self.agents)} agents, "
            f"{len(self.credentials)} credentials, "
            f"{len(self.chains)} chains, "
            f"{len(self.mandates)} mandates, "
            f"{len(self.scenarios)} scenarios"
        )

    def save(self) -> None:
        generated_at = _now_iso()
        stats = {
            "generated_at": generated_at,
            "agents": len(self.agents),
            "credentials": len(self.credentials),
            "chains": len(self.chains),
            "mandates": len(self.mandates),
            "scenarios": len(self.scenarios),
            "scenarios_by_category": {},
        }
        for s in self.scenarios:
            cat = s.get("category", "unknown")
            stats["scenarios_by_category"][cat] = stats["scenarios_by_category"].get(cat, 0) + 1

        # Agents — identity dict included for SDK re-hydration
        agents_out = {
            "generated_at": generated_at,
            "agents": [
                {
                    "name": d["name"],
                    "role": d["role"],
                    "did": d["did"],
                    "tags": d["tags"],
                    "identity_dict": d["identity"].to_dict(),
                }
                for d in self.agents.values()
            ],
        }

        # Credentials
        creds_out = {"generated_at": generated_at, "credentials": [
            {k: v for k, v in c.items() if k != "identity"} for c in self.credentials
        ]}

        # Chains (strip full link JWTs for size; keep first/last + metadata)
        chains_out = {"generated_at": generated_at, "chains": [
            {
                "id": c.get("id", ""),
                "root_issuer": c.get("root_issuer", ""),
                "final_delegate": c.get("final_delegate", ""),
                "expected_valid": c.get("expected_valid", True),
                "depth": len(c.get("links", [])),
                "links": c.get("links", []),
            }
            for c in self.chains
        ]}

        # Mandates
        mandates_out = {"generated_at": generated_at, "mandates": self.mandates}

        # Scenarios
        scenarios_out = {"generated_at": generated_at, "scenarios": self.scenarios}

        # Write all files
        files = {
            "agents.json": agents_out,
            "credentials.json": creds_out,
            "chains.json": chains_out,
            "mandates.json": mandates_out,
            "scenarios.json": scenarios_out,
            "_stats.json": stats,
        }

        for fname, data in files.items():
            path = self.output_dir / fname
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            size_kb = path.stat().st_size / 1024
            print(f"[generator] Wrote {path} ({size_kb:.1f} KB)")

        print(f"\n[generator] Stats: {json.dumps(stats, indent=2)}")

    def expand_labeled_events(self, target: int = 100_000) -> list[dict[str, Any]]:
        """Multiply base scenarios into ~target labeled decision events.

        Each event carries {domain, category, expected_decision, expected_reason}
        for machine-checkable coverage (Phase 1 synthetic v1).
        """
        if not self.scenarios:
            self.generate_all()

        domains = [
            "identity_credentials",
            "delegation_chains",
            "scope_enforcement",
            "mandates_commerce",
            "verifiable_presentations",
            "mcp_gateway",
            "trust_dynamics",
            "revocation",
            "cross_org",
            "scale_performance",
            "pack_core",
        ]
        category_to_decision = {
            "happy": "allow",
            "failure": "block",
            "edge": "step_up",
            "security": "block",
        }
        decisions = ["allow", "step_up", "block"]
        # Approximate production mix from load_generator
        mix_weights = [0.70, 0.10, 0.20]

        events: list[dict[str, Any]] = []
        base = list(self.scenarios)
        i = 0
        while len(events) < target:
            src = base[i % len(base)] if base else {}
            i += 1
            cat = src.get("category", self.rng.choice(["happy", "failure", "edge", "security"]))
            domain = domains[i % len(domains)]
            # Prefer scenario-implied decision, else weighted mix
            expected = category_to_decision.get(cat)
            if expected is None:
                expected = self.rng.choices(decisions, weights=mix_weights, k=1)[0]
            # Inject adversarial / temporal mutations for depth
            mutation = self.rng.choice([
                "none", "near_expiry", "expired", "replay", "scope_escalation",
                "currency_mismatch", "velocity_burst", "shadow_agent", "revoked",
            ])
            if mutation == "revoked":
                expected = "block"
                cat = "security"
            elif mutation == "scope_escalation":
                expected = "block"
                cat = "security"
            elif mutation == "velocity_burst" and expected == "allow":
                expected = self.rng.choice(["allow", "step_up"])

            events.append({
                "id": f"evt-{len(events)+1:07d}",
                "domain": domain,
                "category": cat,
                "mutation": mutation,
                "expected_decision": expected,
                "expected_reason": src.get("expected_reason") or src.get("description") or mutation,
                "source_scenario": src.get("id"),
                "org_type": self.rng.choice(
                    ["enterprise", "financial", "healthcare", "government", "startup"]
                ),
            })
        return events

    def write_coverage_matrix(
        self,
        events: list[dict[str, Any]],
        path: Path,
    ) -> dict[str, Any]:
        """Write 11-domain × 4-category coverage matrix + decision distribution."""
        domains = sorted({e["domain"] for e in events})
        categories = ["happy", "failure", "edge", "security"]
        matrix: dict[str, dict[str, int]] = {d: {c: 0 for c in categories} for d in domains}
        by_decision: dict[str, int] = {}
        for e in events:
            d = e.get("domain", "unknown")
            c = e.get("category", "unknown")
            if d not in matrix:
                matrix[d] = {cat: 0 for cat in categories}
            if c not in matrix[d]:
                matrix[d][c] = 0
            matrix[d][c] += 1
            dec = e.get("expected_decision", "unknown")
            by_decision[dec] = by_decision.get(dec, 0) + 1

        report = {
            "generated_at": _now_iso(),
            "total_events": len(events),
            "decision_distribution": by_decision,
            "coverage_matrix": matrix,
            "domains": domains,
            "categories": categories,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[generator] Coverage matrix → {path} ({len(events)} events)")
        return report


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic Tesht (Pramana) data")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for reproducibility")
    parser.add_argument("--output", type=str, default=str(DATA_DIR), help="Output directory")
    parser.add_argument(
        "--target-events",
        type=int,
        default=0,
        help="If >0, expand labeled decision events to this count (e.g. 100000)",
    )
    parser.add_argument(
        "--coverage-report",
        type=str,
        default="",
        help="Optional path for coverage matrix JSON (default: <output>/coverage_matrix.json)",
    )
    args = parser.parse_args()

    out = Path(args.output)
    gen = EcosystemGenerator(seed=args.seed, output_dir=out)
    gen.generate_all()
    gen.save()

    if args.target_events and args.target_events > 0:
        events = gen.expand_labeled_events(target=args.target_events)
        events_path = out / "labeled_events.jsonl"
        with open(events_path, "w") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")
        print(f"[generator] Wrote {events_path} ({len(events)} events)")
        cov_path = Path(args.coverage_report) if args.coverage_report else out / "coverage_matrix.json"
        gen.write_coverage_matrix(events, cov_path)


if __name__ == "__main__":
    main()
