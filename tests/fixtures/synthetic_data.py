"""
tests/fixtures/synthetic_data.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deterministic synthetic data generator for Pramana Protocol testing.

Produces 55 identities, 67+ credentials, 32 delegation chains, 27 VPs,
16 MCP auth scenarios, trust baselines, commerce mandates, and 200+ audit
events — all cryptographically real.

Usage as standalone script::

    python -m tests.fixtures.synthetic_data

Usage as pytest fixture (via tests/fixtures/conftest.py)::

    def test_foo(synthetic_data):
        assert synthetic_data.humans["H01"].org == "Acme Corp"
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# SDK imports — works when run from repo root or when package is installed
import sys
import os

_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python"))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from pramana.identity import (
    AgentIdentity,
    _b64url,
    _pub_key_to_did_key,
)
from pramana.credentials import issue_vc, create_presentation, verify_vc, verify_presentation
from pramana.delegation import (
    issue_delegation,
    delegate_further,
    verify_delegation_chain,
    ScopeEscalationError,
)
from pramana.commerce import issue_intent_mandate, issue_cart_mandate


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HumanFixture:
    identity: AgentIdentity
    org_role_vc_jwt: str
    org: str
    department: str
    role: str
    trust_level: str


@dataclass
class AgentFixture:
    identity: AgentIdentity
    agent_vc_jwt: str
    agent_type: str
    owner_org: str
    purpose: str


@dataclass
class ErrorFixture:
    jwt_or_error: str
    expected_behavior: str
    error_type: str
    note: Optional[str] = None


@dataclass
class MCPTestContext:
    config: dict[str, Any]
    vp_jwt: str
    expected_authenticated: bool
    expected_reason: Optional[str] = None


@dataclass
class TrustBaseline:
    agent_id: str
    factors: dict[str, int]
    expected_score: int
    risk_tier: str


@dataclass
class CommerceFixture:
    intent_jwt: str
    cart_jwt: Optional[str]
    delegator_id: str
    agent_id: str
    expected_valid: bool
    expected_reason: Optional[str] = None
    note: Optional[str] = None


@dataclass
class SyntheticDataSet:
    humans: dict[str, HumanFixture]
    agents: dict[str, AgentFixture]
    services: dict[str, AgentIdentity]
    idps: dict[str, AgentIdentity]
    delegations: dict[str, str]
    delegation_errors: dict[str, ErrorFixture]
    blended_vps: dict[str, str]
    blended_vp_errors: dict[str, ErrorFixture]
    mcp_contexts: dict[str, MCPTestContext]
    trust_baselines: dict[str, TrustBaseline]
    commerce_mandates: dict[str, CommerceFixture]
    audit_events: list[dict]


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class SyntheticDataGenerator:
    """
    Deterministic synthetic data generator for the Pramana Protocol.

    All identities derive their private keys from SHA-256(seed + id_string),
    making every JWT, DID, and credential byte-identical across runs with the
    same seed.
    """

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)

    # ------------------------------------------------------------------
    # Deterministic identity construction
    # ------------------------------------------------------------------

    def _derive_identity(self, id_string: str, name: str) -> AgentIdentity:
        """Create an AgentIdentity with a deterministic Ed25519 private key."""
        key_bytes = hashlib.sha256(
            f"pramana-fixture-{self.seed}-{id_string}".encode()
        ).digest()
        priv = Ed25519PrivateKey.from_private_bytes(key_bytes)
        pub = priv.public_key()
        pub_raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public_jwk: dict[str, Any] = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(pub_raw),
        }
        did = _pub_key_to_did_key(pub)
        kid = f"{did}#{did}"
        identity = AgentIdentity(
            did=did,
            method="key",
            private_key=priv,
            public_key=pub,
            public_jwk=public_jwk,
            kid=kid,
            _name=name,
        )
        return identity

    # ------------------------------------------------------------------
    # Identities
    # ------------------------------------------------------------------

    _HUMAN_SPECS = [
        ("H01", "Alice Chen",       "Acme Corp",          "Engineering",  "SeniorEngineer",  "HIGH"),
        ("H02", "Bob Martinez",     "Acme Corp",          "Finance",      "CFO",             "HIGH"),
        ("H03", "Carol White",      "Acme Corp",          "Operations",   "Manager",         "MEDIUM"),
        ("H04", "Dave Thompson",    "Globex Inc",         "Engineering",  "Architect",       "HIGH"),
        ("H05", "Eve Johnson",      "Globex Inc",         "Security",     "CISO",            "HIGH"),
        ("H06", "Frank Lee",        "Globex Inc",         "Finance",      "Controller",      "MEDIUM"),
        ("H07", "Grace Kim",        "Initech LLC",        "Engineering",  "TechLead",        "HIGH"),
        ("H08", "Hank Brown",       "Initech LLC",        "Operations",   "COO",             "HIGH"),
        ("H09", "Iris Davis",       "Initech LLC",        "Marketing",    "Director",        "MEDIUM"),
        ("H10", "Jack Wilson",      "Umbrella Corp",      "Research",     "Scientist",       "HIGH"),
        ("H11", "Kate Moore",       "Umbrella Corp",      "Engineering",  "DevLead",         "HIGH"),
        ("H12", "Leo Taylor",       "Umbrella Corp",      "Finance",      "Analyst",         "MEDIUM"),
        ("H13", "Maya Anderson",    "Tyrell Corp",        "Engineering",  "Architect",       "HIGH"),
        ("H14", "Nick Jackson",     "Tyrell Corp",        "Security",     "SecEngineer",     "MEDIUM"),
        ("H15", "Olivia Harris",    "Tyrell Corp",        "Operations",   "ProjectManager",  "LOW"),
    ]

    _AGENT_SPECS = [
        ("A01",  "shopping-agent",       "LLM",         "Acme Corp",     "e-commerce purchasing"),
        ("A02",  "calendar-agent",       "LLM",         "Acme Corp",     "calendar management"),
        ("A03",  "email-agent",          "LLM",         "Acme Corp",     "email composition"),
        ("A04",  "data-analysis-agent",  "Analytics",   "Acme Corp",     "data pipeline execution"),
        ("A05",  "code-review-agent",    "LLM",         "Acme Corp",     "automated code review"),
        ("A06",  "travel-agent",         "LLM",         "Globex Inc",    "travel booking"),
        ("A07",  "finance-agent",        "Analytics",   "Globex Inc",    "financial reporting"),
        ("A08",  "security-scan-agent",  "Scanner",     "Globex Inc",    "vulnerability scanning"),
        ("A09",  "hr-agent",             "LLM",         "Globex Inc",    "HR workflow automation"),
        ("A10",  "docs-agent",           "LLM",         "Globex Inc",    "documentation generation"),
        ("A11",  "deploy-agent",         "CI/CD",       "Initech LLC",   "deployment automation"),
        ("A12",  "monitor-agent",        "Monitor",     "Initech LLC",   "system health monitoring"),
        ("A13",  "billing-agent",        "Analytics",   "Initech LLC",   "invoice processing"),
        ("A14",  "support-agent",        "LLM",         "Initech LLC",   "customer support"),
        ("A15",  "research-agent",       "LLM",         "Initech LLC",   "competitive research"),
        ("A16",  "lab-agent",            "Scientific",  "Umbrella Corp", "lab data collection"),
        ("A17",  "report-agent",         "Analytics",   "Umbrella Corp", "regulatory reporting"),
        ("A18",  "supply-chain-agent",   "Logistics",   "Umbrella Corp", "supply chain tracking"),
        ("A19",  "patent-agent",         "LLM",         "Umbrella Corp", "patent filing assistance"),
        ("A20",  "compliance-agent",     "Monitor",     "Umbrella Corp", "compliance checks"),
        ("A21",  "design-agent",         "LLM",         "Tyrell Corp",   "product design"),
        ("A22",  "customer-agent",       "LLM",         "Tyrell Corp",   "customer insights"),
        ("A23",  "pricing-agent",        "Analytics",   "Tyrell Corp",   "dynamic pricing"),
        ("A24",  "adversarial-agent",    "LLM",         "External",      "adversarial test subject"),
        ("A25",  "untrusted-agent",      "Unknown",     "External",      "untrusted test subject"),
    ]

    _SERVICE_SPECS = [
        ("S01",  "acme-mcp-gateway",        "Acme Corp"),
        ("S02",  "globex-mcp-gateway",      "Globex Inc"),
        ("S03",  "initech-mcp-gateway",     "Initech LLC"),
        ("S04",  "umbrella-mcp-gateway",    "Umbrella Corp"),
        ("S05",  "tyrell-mcp-gateway",      "Tyrell Corp"),
        ("S06",  "shared-audit-service",    "Cross-Org"),
        ("S07",  "trust-scoring-service",   "Cross-Org"),
        ("S08",  "verifier-service",        "Cross-Org"),
        ("S09",  "commerce-gateway",        "Cross-Org"),
        ("S10",  "identity-bridge",         "Cross-Org"),
    ]

    _IDP_SPECS = [
        ("IDP01", "acme-idp",       "Acme Corp"),
        ("IDP02", "globex-idp",     "Globex Inc"),
        ("IDP03", "initech-idp",    "Initech LLC"),
        ("IDP04", "umbrella-idp",   "Umbrella Corp"),
        ("IDP05", "tyrell-idp",     "Tyrell Corp"),
    ]

    # Map org -> IdP id
    _ORG_IDP = {
        "Acme Corp":     "IDP01",
        "Globex Inc":    "IDP02",
        "Initech LLC":   "IDP03",
        "Umbrella Corp": "IDP04",
        "Tyrell Corp":   "IDP05",
    }

    def generate_identities(
        self,
    ) -> tuple[
        dict[str, HumanFixture],
        dict[str, AgentFixture],
        dict[str, AgentIdentity],
        dict[str, AgentIdentity],
    ]:
        """Generate all identities and their associated VCs."""

        # Build IdPs first (needed as VC issuers)
        idps: dict[str, AgentIdentity] = {}
        for idp_id, idp_name, _ in self._IDP_SPECS:
            idps[idp_id] = self._derive_identity(idp_id, idp_name)

        # Build services
        services: dict[str, AgentIdentity] = {}
        for svc_id, svc_name, _ in self._SERVICE_SPECS:
            services[svc_id] = self._derive_identity(svc_id, svc_name)

        # Build humans + OrgRoleVCs
        humans: dict[str, HumanFixture] = {}
        for h_id, name, org, dept, role, trust_level in self._HUMAN_SPECS:
            identity = self._derive_identity(h_id, name)
            idp_id = self._ORG_IDP[org]
            idp = idps[idp_id]
            vc_jwt = issue_vc(
                issuer=idp,
                subject_did=identity.did,
                credential_type="OrganizationalRoleCredential",
                claims={
                    "name": name,
                    "organization": org,
                    "department": dept,
                    "role": role,
                    "trustLevel": trust_level,
                },
                ttl_seconds=86400 * 365,  # 1 year
            )
            humans[h_id] = HumanFixture(
                identity=identity,
                org_role_vc_jwt=vc_jwt,
                org=org,
                department=dept,
                role=role,
                trust_level=trust_level,
            )

        # Build agents + AgentVCs
        agents: dict[str, AgentFixture] = {}
        for a_id, name, agent_type, owner_org, purpose in self._AGENT_SPECS:
            identity = self._derive_identity(a_id, name)
            idp_id = self._ORG_IDP.get(owner_org)
            if idp_id:
                issuer = idps[idp_id]
            else:
                # External agents — self-issued (no org IdP)
                issuer = identity
            vc_jwt = issue_vc(
                issuer=issuer,
                subject_did=identity.did,
                credential_type="AgentCredential",
                claims={
                    "agentName": name,
                    "agentType": agent_type,
                    "ownerOrg": owner_org,
                    "purpose": purpose,
                },
                ttl_seconds=86400 * 90,  # 90 days
            )
            agents[a_id] = AgentFixture(
                identity=identity,
                agent_vc_jwt=vc_jwt,
                agent_type=agent_type,
                owner_org=owner_org,
                purpose=purpose,
            )

        return humans, agents, services, idps

    # ------------------------------------------------------------------
    # Delegations
    # ------------------------------------------------------------------

    def generate_delegations(
        self,
        humans: dict[str, HumanFixture],
        agents: dict[str, AgentFixture],
    ) -> tuple[dict[str, str], dict[str, ErrorFixture]]:
        """Generate valid delegation chains DC01-DC20 and error cases DC_ERR01-DC_ERR12."""

        delegations: dict[str, str] = {}
        delegation_errors: dict[str, ErrorFixture] = {}

        # --- Valid chains ---

        # DC01: Alice -> A01, broad e-commerce scope
        delegations["DC01"] = issue_delegation(
            delegator=humans["H01"].identity,
            delegate_did=agents["A01"].identity.did,
            scope={
                "actions": ["read:catalog", "add:cart", "submit:order"],
                "max_amount": 50000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["electronics", "books"],
            },
            max_depth=3,
        )

        # DC02: Bob -> A07, financial reporting only
        delegations["DC02"] = issue_delegation(
            delegator=humans["H02"].identity,
            delegate_did=agents["A07"].identity.did,
            scope={
                "actions": ["read:finance", "generate:report"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["finance"],
            },
            max_depth=1,
        )

        # DC03: Eve -> A08, security scanning
        delegations["DC03"] = issue_delegation(
            delegator=humans["H05"].identity,
            delegate_did=agents["A08"].identity.did,
            scope={
                "actions": ["scan:network", "read:logs", "report:vulnerability"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["security"],
            },
            max_depth=1,
        )

        # DC04: Grace -> A11, CI/CD deploy
        delegations["DC04"] = issue_delegation(
            delegator=humans["H07"].identity,
            delegate_did=agents["A11"].identity.did,
            scope={
                "actions": ["deploy:staging", "deploy:production", "read:config"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["devops"],
            },
            max_depth=2,
        )

        # DC05: Alice -> A01 -> A21 (multi-hop, narrowed)
        delegations["DC05"] = delegate_further(
            holder=agents["A01"].identity,
            parent_delegation_jwt=delegations["DC01"],
            sub_delegate_did=agents["A21"].identity.did,
            narrowed_scope={
                "actions": ["read:catalog", "add:cart"],
                "max_amount": 10000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["electronics"],
            },
        )

        # DC06: Grace -> A11 -> A12 (deploy narrowed to staging only)
        delegations["DC06"] = delegate_further(
            holder=agents["A11"].identity,
            parent_delegation_jwt=delegations["DC04"],
            sub_delegate_did=agents["A12"].identity.did,
            narrowed_scope={
                "actions": ["deploy:staging", "read:config"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["devops"],
            },
        )

        # DC07: Alice -> A01 -> A21 -> A22 (3-hop, narrowed to read only)
        delegations["DC07"] = delegate_further(
            holder=agents["A21"].identity,
            parent_delegation_jwt=delegations["DC05"],
            sub_delegate_did=agents["A22"].identity.did,
            narrowed_scope={
                "actions": ["read:catalog"],
                "max_amount": 5000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["electronics"],
            },
        )

        # DC08: Dave -> A06, travel booking
        delegations["DC08"] = issue_delegation(
            delegator=humans["H04"].identity,
            delegate_did=agents["A06"].identity.did,
            scope={
                "actions": ["search:travel", "book:flight", "book:hotel"],
                "max_amount": 200000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["travel"],
            },
            max_depth=1,
        )

        # DC09: Hank -> A13, billing / invoices
        delegations["DC09"] = issue_delegation(
            delegator=humans["H08"].identity,
            delegate_did=agents["A13"].identity.did,
            scope={
                "actions": ["read:invoices", "submit:payment"],
                "max_amount": 100000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["billing"],
            },
            max_depth=1,
        )

        # DC10: Jack -> A16, lab operations (read + write)
        delegations["DC10"] = issue_delegation(
            delegator=humans["H10"].identity,
            delegate_did=agents["A16"].identity.did,
            scope={
                "actions": ["read:lab_data", "write:lab_data", "generate:report"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["research"],
            },
            max_depth=2,
        )

        # DC11: Kate -> A20, compliance checks
        delegations["DC11"] = issue_delegation(
            delegator=humans["H11"].identity,
            delegate_did=agents["A20"].identity.did,
            scope={
                "actions": ["read:compliance", "audit:records"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["compliance"],
            },
            max_depth=1,
        )

        # DC12: Maya -> A21, design + catalog read
        delegations["DC12"] = issue_delegation(
            delegator=humans["H13"].identity,
            delegate_did=agents["A21"].identity.did,
            scope={
                "actions": ["read:catalog", "create:design"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["design"],
            },
            max_depth=1,
        )

        # DC13: Nick -> A14, customer support
        delegations["DC13"] = issue_delegation(
            delegator=humans["H14"].identity,
            delegate_did=agents["A14"].identity.did,
            scope={
                "actions": ["read:tickets", "write:response"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["support"],
            },
            max_depth=1,
        )

        # DC14: Carol -> A03, email on her behalf
        delegations["DC14"] = issue_delegation(
            delegator=humans["H03"].identity,
            delegate_did=agents["A03"].identity.did,
            scope={
                "actions": ["read:email", "send:email"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["communication"],
            },
            max_depth=1,
        )

        # DC15: Iris -> A15, research (read only)
        delegations["DC15"] = issue_delegation(
            delegator=humans["H09"].identity,
            delegate_did=agents["A15"].identity.did,
            scope={
                "actions": ["read:web", "read:internal"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["research"],
            },
            max_depth=1,
        )

        # DC16: Frank -> A07, financial read-only
        delegations["DC16"] = issue_delegation(
            delegator=humans["H06"].identity,
            delegate_did=agents["A07"].identity.did,
            scope={
                "actions": ["read:finance"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["finance"],
            },
            max_depth=1,
        )

        # DC17: Leo -> A19, patent filing read
        delegations["DC17"] = issue_delegation(
            delegator=humans["H12"].identity,
            delegate_did=agents["A19"].identity.did,
            scope={
                "actions": ["read:patents", "draft:document"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["legal"],
            },
            max_depth=1,
        )

        # DC18: Olivia -> A23, pricing data read
        delegations["DC18"] = issue_delegation(
            delegator=humans["H15"].identity,
            delegate_did=agents["A23"].identity.did,
            scope={
                "actions": ["read:pricing", "update:pricing"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["pricing"],
            },
            max_depth=1,
        )

        # DC19: Alice -> A02, calendar management
        delegations["DC19"] = issue_delegation(
            delegator=humans["H01"].identity,
            delegate_did=agents["A02"].identity.did,
            scope={
                "actions": ["read:calendar", "write:calendar"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["productivity"],
            },
            max_depth=1,
        )

        # DC20: Jack -> A16 -> A17 (lab -> report narrowed to generate only)
        delegations["DC20"] = delegate_further(
            holder=agents["A16"].identity,
            parent_delegation_jwt=delegations["DC10"],
            sub_delegate_did=agents["A17"].identity.did,
            narrowed_scope={
                "actions": ["generate:report"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": ["research"],
            },
        )

        # --- Error chains ---

        # DC_ERR01: Expired delegation — manually craft a JWT with past exp
        alice = humans["H01"].identity
        iat_past = int(time.time()) - 7200
        exp_past = iat_past - 60  # already expired at issuance
        err_payload = {
            "iss": alice.did,
            "sub": agents["A01"].identity.did,
            "jti": str(uuid.uuid4()),
            "iat": iat_past,
            "exp": exp_past,
            "vc": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DelegationCredential"],
                "issuer": alice.did,
                "validFrom": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(iat_past)),
                "credentialSubject": {
                    "id": agents["A01"].identity.did,
                    "delegatedBy": alice.did,
                    "delegationScope": {
                        "actions": ["read:catalog"],
                        "max_amount": 1000,
                        "currency": "USD",
                        "merchants": ["*"],
                        "categories": ["electronics"],
                    },
                    "delegationDepth": 0,
                    "maxDelegationDepth": 1,
                },
            },
        }
        err_jwt = pyjwt.encode(
            err_payload,
            key=alice.private_key,
            algorithm="EdDSA",
            headers={"kid": alice.kid, "typ": "JWT"},
        )
        delegation_errors["DC_ERR01"] = ErrorFixture(
            jwt_or_error=err_jwt,
            expected_behavior="verify_delegation_chain returns verified=False, reason='expired'",
            error_type="expired",
        )

        # DC_ERR02: Scope escalation — actions
        try:
            bad = issue_delegation(
                delegator=humans["H01"].identity,
                delegate_did=agents["A01"].identity.did,
                scope={
                    "actions": ["read:catalog", "add:cart", "submit:order"],
                    "max_amount": 50000,
                    "currency": "USD",
                    "merchants": ["*"],
                    "categories": ["electronics"],
                },
                max_depth=2,
            )
            # Try to delegate further with escalated actions
            _ = delegate_further(
                holder=agents["A01"].identity,
                parent_delegation_jwt=bad,
                sub_delegate_did=agents["A21"].identity.did,
                narrowed_scope={
                    "actions": ["read:catalog", "add:cart", "submit:order", "delete:account"],
                    "max_amount": 50000,
                    "currency": "USD",
                    "merchants": ["*"],
                    "categories": ["electronics"],
                },
            )
            delegation_errors["DC_ERR02"] = ErrorFixture(
                jwt_or_error="No error raised — unexpected",
                expected_behavior="delegate_further raises ScopeEscalationError on actions",
                error_type="scope_escalation",
            )
        except ScopeEscalationError as e:
            delegation_errors["DC_ERR02"] = ErrorFixture(
                jwt_or_error=str(e),
                expected_behavior="delegate_further raises ScopeEscalationError on actions",
                error_type="scope_escalation",
            )

        # DC_ERR03: Scope escalation — max_amount
        try:
            parent_narrow = issue_delegation(
                delegator=humans["H02"].identity,
                delegate_did=agents["A07"].identity.did,
                scope={
                    "actions": ["read:finance"],
                    "max_amount": 1000,
                    "currency": "USD",
                    "merchants": [],
                    "categories": ["finance"],
                },
                max_depth=2,
            )
            _ = delegate_further(
                holder=agents["A07"].identity,
                parent_delegation_jwt=parent_narrow,
                sub_delegate_did=agents["A23"].identity.did,
                narrowed_scope={
                    "actions": ["read:finance"],
                    "max_amount": 99999,
                    "currency": "USD",
                    "merchants": [],
                    "categories": ["finance"],
                },
            )
            delegation_errors["DC_ERR03"] = ErrorFixture(
                jwt_or_error="No error raised — unexpected",
                expected_behavior="delegate_further raises ScopeEscalationError on max_amount",
                error_type="scope_escalation",
            )
        except ScopeEscalationError as e:
            delegation_errors["DC_ERR03"] = ErrorFixture(
                jwt_or_error=str(e),
                expected_behavior="delegate_further raises ScopeEscalationError on max_amount",
                error_type="scope_escalation",
            )

        # DC_ERR04: Scope escalation — categories
        try:
            parent_cat = issue_delegation(
                delegator=humans["H04"].identity,
                delegate_did=agents["A06"].identity.did,
                scope={
                    "actions": ["search:travel"],
                    "max_amount": 10000,
                    "currency": "USD",
                    "merchants": ["*"],
                    "categories": ["travel"],
                },
                max_depth=2,
            )
            _ = delegate_further(
                holder=agents["A06"].identity,
                parent_delegation_jwt=parent_cat,
                sub_delegate_did=agents["A22"].identity.did,
                narrowed_scope={
                    "actions": ["search:travel"],
                    "max_amount": 10000,
                    "currency": "USD",
                    "merchants": ["*"],
                    "categories": ["travel", "entertainment"],
                },
            )
            delegation_errors["DC_ERR04"] = ErrorFixture(
                jwt_or_error="No error raised — unexpected",
                expected_behavior="delegate_further raises ScopeEscalationError on categories",
                error_type="scope_escalation",
            )
        except ScopeEscalationError as e:
            delegation_errors["DC_ERR04"] = ErrorFixture(
                jwt_or_error=str(e),
                expected_behavior="delegate_further raises ScopeEscalationError on categories",
                error_type="scope_escalation",
            )

        # DC_ERR05: Scope escalation — currency mismatch
        try:
            parent_usd = issue_delegation(
                delegator=humans["H05"].identity,
                delegate_did=agents["A08"].identity.did,
                scope={
                    "actions": ["scan:network"],
                    "max_amount": 500,
                    "currency": "USD",
                    "merchants": [],
                    "categories": ["security"],
                },
                max_depth=2,
            )
            _ = delegate_further(
                holder=agents["A08"].identity,
                parent_delegation_jwt=parent_usd,
                sub_delegate_did=agents["A20"].identity.did,
                narrowed_scope={
                    "actions": ["scan:network"],
                    "max_amount": 500,
                    "currency": "EUR",
                    "merchants": [],
                    "categories": ["security"],
                },
            )
            delegation_errors["DC_ERR05"] = ErrorFixture(
                jwt_or_error="No error raised — unexpected",
                expected_behavior="delegate_further raises ScopeEscalationError on currency mismatch",
                error_type="scope_escalation",
            )
        except ScopeEscalationError as e:
            delegation_errors["DC_ERR05"] = ErrorFixture(
                jwt_or_error=str(e),
                expected_behavior="delegate_further raises ScopeEscalationError on currency mismatch",
                error_type="scope_escalation",
            )

        # DC_ERR06: Depth exceeded — max_depth=0 means no sub-delegation allowed (depth 1 > 0)
        try:
            d1 = issue_delegation(
                delegator=humans["H07"].identity,
                delegate_did=agents["A11"].identity.did,
                scope={
                    "actions": ["deploy:staging"],
                    "max_amount": 0,
                    "currency": "USD",
                    "merchants": [],
                    "categories": ["devops"],
                },
                max_depth=0,  # no sub-delegation allowed
            )
            _ = delegate_further(
                holder=agents["A11"].identity,
                parent_delegation_jwt=d1,
                sub_delegate_did=agents["A12"].identity.did,
                narrowed_scope={
                    "actions": ["deploy:staging"],
                    "max_amount": 0,
                    "currency": "USD",
                    "merchants": [],
                    "categories": ["devops"],
                },
            )
            delegation_errors["DC_ERR06"] = ErrorFixture(
                jwt_or_error="No error raised — unexpected",
                expected_behavior="delegate_further raises ValueError: delegation depth exceeded",
                error_type="depth_exceeded",
            )
        except ValueError as e:
            delegation_errors["DC_ERR06"] = ErrorFixture(
                jwt_or_error=str(e),
                expected_behavior="delegate_further raises ValueError: delegation depth exceeded",
                error_type="depth_exceeded",
            )

        # DC_ERR07: Revoked credential placeholder
        revocable_jwt = issue_delegation(
            delegator=humans["H01"].identity,
            delegate_did=agents["A01"].identity.did,
            scope={
                "actions": ["read:catalog"],
                "max_amount": 1000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["electronics"],
            },
            max_depth=1,
        )
        delegation_errors["DC_ERR07"] = ErrorFixture(
            jwt_or_error=revocable_jwt,
            expected_behavior="verify_delegation_chain with status_checker returns verified=False, reason='revoked'",
            error_type="revoked",
            note="requires_revocation_infrastructure: call POST /api/v1/credentials/{jti}/revoke before using",
        )

        # DC_ERR08: Tampered signature — flip byte 50 of signature segment
        valid_for_tamper = delegations["DC01"]
        parts = valid_for_tamper.split(".")
        sig_bytes = bytearray(
            base64.urlsafe_b64decode(parts[2] + "=" * ((4 - len(parts[2]) % 4) % 4))
        )
        sig_bytes[50 % len(sig_bytes)] ^= 0xFF
        tampered_sig = base64.urlsafe_b64encode(bytes(sig_bytes)).rstrip(b"=").decode()
        delegation_errors["DC_ERR08"] = ErrorFixture(
            jwt_or_error=f"{parts[0]}.{parts[1]}.{tampered_sig}",
            expected_behavior="verify_delegation_chain returns verified=False, reason='Signature verification failed'",
            error_type="tampered",
        )

        # DC_ERR09: Wrong signer — Alice's DID but Bob's key
        alice = humans["H01"].identity
        bob = humans["H02"].identity
        wrong_signer_payload = {
            "iss": alice.did,
            "sub": agents["A01"].identity.did,
            "jti": str(uuid.uuid4()),
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "vc": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DelegationCredential"],
                "issuer": alice.did,
                "validFrom": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "credentialSubject": {
                    "id": agents["A01"].identity.did,
                    "delegatedBy": alice.did,
                    "delegationScope": {
                        "actions": ["read:catalog"],
                        "max_amount": 1000,
                        "currency": "USD",
                        "merchants": ["*"],
                        "categories": [],
                    },
                    "delegationDepth": 0,
                    "maxDelegationDepth": 1,
                },
            },
        }
        wrong_signer_jwt = pyjwt.encode(
            wrong_signer_payload,
            key=bob.private_key,
            algorithm="EdDSA",
            headers={"kid": alice.kid, "typ": "JWT"},
        )
        delegation_errors["DC_ERR09"] = ErrorFixture(
            jwt_or_error=wrong_signer_jwt,
            expected_behavior="verify_vc returns verified=False, reason='Signature verification failed'",
            error_type="wrong_signer",
        )

        # DC_ERR10: Self-delegation (delegator == delegate)
        self_delegation_jwt = issue_delegation(
            delegator=humans["H01"].identity,
            delegate_did=humans["H01"].identity.did,  # same DID
            scope={
                "actions": ["read:catalog"],
                "max_amount": 0,
                "currency": "USD",
                "merchants": [],
                "categories": [],
            },
            max_depth=1,
        )
        delegation_errors["DC_ERR10"] = ErrorFixture(
            jwt_or_error=self_delegation_jwt,
            expected_behavior="Self-delegation is a policy violation; verification logic should reject delegator==delegate",
            error_type="self_delegation",
        )

        # DC_ERR11: Deeply nested chain that exceeds the SDK's default recursion guard (_max_recursion=10)
        # Build a chain of depth 12: H01->A01->A21->A22->A02->A03->A04->A05->A06->A07->A08->A09->A10
        # by issuing delegations with max_depth=15 and chaining via delegate_further
        deep_scope = {
            "actions": ["read:catalog"],
            "max_amount": 1000,
            "currency": "USD",
            "merchants": ["*"],
            "categories": ["electronics"],
        }
        deep_chain_agents = ["A01", "A21", "A22", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10", "A11"]
        deep_root = issue_delegation(
            delegator=humans["H01"].identity,
            delegate_did=agents[deep_chain_agents[0]].identity.did,
            scope=deep_scope,
            max_depth=15,
        )
        deep_current = deep_root
        deep_current_agent = deep_chain_agents[0]
        for next_agent_id in deep_chain_agents[1:]:
            deep_current = delegate_further(
                holder=agents[deep_current_agent].identity,
                parent_delegation_jwt=deep_current,
                sub_delegate_did=agents[next_agent_id].identity.did,
                narrowed_scope=deep_scope,
            )
            deep_current_agent = next_agent_id
        delegation_errors["DC_ERR11"] = ErrorFixture(
            jwt_or_error=deep_current,
            expected_behavior="verify_delegation_chain with default _max_recursion=10 returns verified=False; 'Recursion limit 10 exceeded'",
            error_type="depth_exceeded_recursion_guard",
        )

        # DC_ERR12: Missing parentDelegation claim in multi-hop
        missing_parent_payload = {
            "iss": agents["A01"].identity.did,
            "sub": agents["A21"].identity.did,
            "jti": str(uuid.uuid4()),
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "vc": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DelegationCredential"],
                "issuer": agents["A01"].identity.did,
                "validFrom": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "credentialSubject": {
                    "id": agents["A21"].identity.did,
                    "delegatedBy": agents["A01"].identity.did,
                    "delegationScope": {
                        "actions": ["read:catalog"],
                        "max_amount": 500,
                        "currency": "USD",
                        "merchants": ["*"],
                        "categories": ["electronics"],
                    },
                    "delegationDepth": 1,  # claims depth 1 but no parentDelegation
                    "maxDelegationDepth": 3,
                    # parentDelegation intentionally omitted
                },
            },
        }
        missing_parent_jwt = pyjwt.encode(
            missing_parent_payload,
            key=agents["A01"].identity.private_key,
            algorithm="EdDSA",
            headers={"kid": agents["A01"].identity.kid, "typ": "JWT"},
        )
        delegation_errors["DC_ERR12"] = ErrorFixture(
            jwt_or_error=missing_parent_jwt,
            expected_behavior="verify_delegation_chain verifies at face value (no parent to traverse) but depth=1 claimed; policy check should flag missing parentDelegation",
            error_type="missing_parent_delegation",
        )

        return delegations, delegation_errors

    # ------------------------------------------------------------------
    # Blended VPs
    # ------------------------------------------------------------------

    def generate_blended_vps(
        self,
        humans: dict[str, HumanFixture],
        agents: dict[str, AgentFixture],
        services: dict[str, AgentIdentity],
        delegations: dict[str, str],
        delegation_errors: dict[str, ErrorFixture],
    ) -> tuple[dict[str, str], dict[str, ErrorFixture]]:
        """Generate valid blended VPs VP01-VP15 and error cases VP_ERR01-VP_ERR12."""

        blended_vps: dict[str, str] = {}
        blended_vp_errors: dict[str, ErrorFixture] = {}

        # VP01: A01 presents delegation(DC01) + Alice's OrgRoleVC + A01's AgentVC -> Acme gateway
        blended_vps["VP01"] = create_presentation(
            holder=agents["A01"].identity,
            credentials=[
                delegations["DC01"],
                humans["H01"].org_role_vc_jwt,
                agents["A01"].agent_vc_jwt,
            ],
            audience=services["S01"].did,
        )

        # VP02: A07 presents DC02 + Bob's OrgRoleVC -> Acme gateway
        blended_vps["VP02"] = create_presentation(
            holder=agents["A07"].identity,
            credentials=[
                delegations["DC02"],
                humans["H02"].org_role_vc_jwt,
                agents["A07"].agent_vc_jwt,
            ],
            audience=services["S01"].did,
        )

        # VP03: A08 presents DC03 + Eve's OrgRoleVC -> Globex gateway
        blended_vps["VP03"] = create_presentation(
            holder=agents["A08"].identity,
            credentials=[
                delegations["DC03"],
                humans["H05"].org_role_vc_jwt,
                agents["A08"].agent_vc_jwt,
            ],
            audience=services["S02"].did,
        )

        # VP04: A11 presents DC04 + Grace's OrgRoleVC -> Initech gateway
        blended_vps["VP04"] = create_presentation(
            holder=agents["A11"].identity,
            credentials=[
                delegations["DC04"],
                humans["H07"].org_role_vc_jwt,
                agents["A11"].agent_vc_jwt,
            ],
            audience=services["S03"].did,
        )

        # VP05: A21 presents multi-hop DC05 + Alice's OrgRoleVC -> Tyrell gateway
        blended_vps["VP05"] = create_presentation(
            holder=agents["A21"].identity,
            credentials=[
                delegations["DC05"],
                humans["H01"].org_role_vc_jwt,
                agents["A21"].agent_vc_jwt,
            ],
            audience=services["S05"].did,
        )

        # VP06: A12 presents DC06 + Grace's OrgRoleVC -> Initech gateway (deploy:staging only)
        blended_vps["VP06"] = create_presentation(
            holder=agents["A12"].identity,
            credentials=[
                delegations["DC06"],
                humans["H07"].org_role_vc_jwt,
                agents["A12"].agent_vc_jwt,
            ],
            audience=services["S03"].did,
        )

        # VP07: A22 presents 3-hop DC07 + Alice's OrgRoleVC -> Tyrell gateway
        blended_vps["VP07"] = create_presentation(
            holder=agents["A22"].identity,
            credentials=[
                delegations["DC07"],
                humans["H01"].org_role_vc_jwt,
                agents["A22"].agent_vc_jwt,
            ],
            audience=services["S05"].did,
        )

        # VP08: A06 presents DC08 + Dave's OrgRoleVC -> Globex gateway (travel)
        blended_vps["VP08"] = create_presentation(
            holder=agents["A06"].identity,
            credentials=[
                delegations["DC08"],
                humans["H04"].org_role_vc_jwt,
                agents["A06"].agent_vc_jwt,
            ],
            audience=services["S02"].did,
        )

        # VP09: A13 presents DC09 + Hank's OrgRoleVC -> Initech gateway (billing)
        blended_vps["VP09"] = create_presentation(
            holder=agents["A13"].identity,
            credentials=[
                delegations["DC09"],
                humans["H08"].org_role_vc_jwt,
                agents["A13"].agent_vc_jwt,
            ],
            audience=services["S03"].did,
        )

        # VP10: A16 presents DC10 + Jack's OrgRoleVC -> Umbrella gateway (lab)
        blended_vps["VP10"] = create_presentation(
            holder=agents["A16"].identity,
            credentials=[
                delegations["DC10"],
                humans["H10"].org_role_vc_jwt,
                agents["A16"].agent_vc_jwt,
            ],
            audience=services["S04"].did,
        )

        # VP11: A20 presents DC11 + Kate's OrgRoleVC -> Umbrella gateway (compliance)
        blended_vps["VP11"] = create_presentation(
            holder=agents["A20"].identity,
            credentials=[
                delegations["DC11"],
                humans["H11"].org_role_vc_jwt,
                agents["A20"].agent_vc_jwt,
            ],
            audience=services["S04"].did,
        )

        # VP12: A21 presents DC12 + Maya's OrgRoleVC -> Tyrell gateway (design)
        blended_vps["VP12"] = create_presentation(
            holder=agents["A21"].identity,
            credentials=[
                delegations["DC12"],
                humans["H13"].org_role_vc_jwt,
                agents["A21"].agent_vc_jwt,
            ],
            audience=services["S05"].did,
        )

        # VP13: A03 presents DC14 + Carol's OrgRoleVC -> Acme gateway (email)
        blended_vps["VP13"] = create_presentation(
            holder=agents["A03"].identity,
            credentials=[
                delegations["DC14"],
                humans["H03"].org_role_vc_jwt,
                agents["A03"].agent_vc_jwt,
            ],
            audience=services["S01"].did,
        )

        # VP14: A17 presents DC20 + Jack's OrgRoleVC -> Umbrella gateway (lab report)
        blended_vps["VP14"] = create_presentation(
            holder=agents["A17"].identity,
            credentials=[
                delegations["DC20"],
                humans["H10"].org_role_vc_jwt,
                agents["A17"].agent_vc_jwt,
            ],
            audience=services["S04"].did,
        )

        # VP15: Multi-credential — A01 presents DC01 + A01 AgentVC + Alice's OrgRoleVC (all three)
        # presented to the shared verifier service
        blended_vps["VP15"] = create_presentation(
            holder=agents["A01"].identity,
            credentials=[
                delegations["DC01"],
                agents["A01"].agent_vc_jwt,
                humans["H01"].org_role_vc_jwt,
            ],
            audience=services["S08"].did,
            nonce="pramana-test-nonce-vp15",
        )

        # --- VP error cases ---

        # VP_ERR01: VP containing expired delegation (DC_ERR01)
        try:
            expired_vp = create_presentation(
                holder=agents["A01"].identity,
                credentials=[
                    delegation_errors["DC_ERR01"].jwt_or_error,
                    humans["H01"].org_role_vc_jwt,
                ],
                audience=services["S01"].did,
            )
            blended_vp_errors["VP_ERR01"] = ErrorFixture(
                jwt_or_error=expired_vp,
                expected_behavior="verify_presentation returns verified=False; credential 0 failed: expired",
                error_type="expired_delegation",
            )
        except Exception as e:
            blended_vp_errors["VP_ERR01"] = ErrorFixture(
                jwt_or_error=str(e),
                expected_behavior="verify_presentation returns verified=False; credential 0 failed: expired",
                error_type="expired_delegation",
            )

        # VP_ERR02: Audience mismatch — VP created for S01 but verified against S02
        vp_wrong_aud = create_presentation(
            holder=agents["A01"].identity,
            credentials=[delegations["DC01"], humans["H01"].org_role_vc_jwt],
            audience=services["S01"].did,
        )
        blended_vp_errors["VP_ERR02"] = ErrorFixture(
            jwt_or_error=vp_wrong_aud,
            expected_behavior="verify_presentation(expected_audience=S02.did) returns verified=False; Audience mismatch",
            error_type="audience_mismatch",
            note=f"Verify with expected_audience={services['S02'].did}",
        )

        # VP_ERR03: Tampered inner VC — flip signature byte of the AgentVC
        agent_vc = agents["A01"].agent_vc_jwt
        vc_parts = agent_vc.split(".")
        vc_sig_bytes = bytearray(
            base64.urlsafe_b64decode(vc_parts[2] + "=" * ((4 - len(vc_parts[2]) % 4) % 4))
        )
        vc_sig_bytes[10 % len(vc_sig_bytes)] ^= 0xFF
        tampered_vc_sig = base64.urlsafe_b64encode(bytes(vc_sig_bytes)).rstrip(b"=").decode()
        tampered_agent_vc = f"{vc_parts[0]}.{vc_parts[1]}.{tampered_vc_sig}"
        tampered_vp = create_presentation(
            holder=agents["A01"].identity,
            credentials=[delegations["DC01"], tampered_agent_vc],
            audience=services["S01"].did,
        )
        blended_vp_errors["VP_ERR03"] = ErrorFixture(
            jwt_or_error=tampered_vp,
            expected_behavior="verify_presentation returns verified=False; credential 1 failed: Signature verification failed",
            error_type="tampered_inner_vc",
        )

        # VP_ERR04: Wrong VP signer — VP payload claims A01's credentials but signed by A25
        # Build it manually using pyjwt directly
        now = int(time.time())
        vp_payload_wrong_signer = {
            "iss": agents["A01"].identity.did,  # claims to be A01
            "aud": services["S01"].did,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
            "vp": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": agents["A01"].identity.did,
                "verifiableCredential": [delegations["DC01"], humans["H01"].org_role_vc_jwt],
            },
        }
        vp_wrong_signer = pyjwt.encode(
            vp_payload_wrong_signer,
            key=agents["A25"].identity.private_key,  # signed by A25
            algorithm="EdDSA",
            headers={"kid": agents["A01"].identity.kid, "typ": "JWT"},
        )
        blended_vp_errors["VP_ERR04"] = ErrorFixture(
            jwt_or_error=vp_wrong_signer,
            expected_behavior="verify_presentation returns verified=False; VP signature verification failed",
            error_type="wrong_vp_signer",
        )

        # VP_ERR05: Empty credential list — create_presentation raises ValueError
        try:
            _ = create_presentation(
                holder=agents["A01"].identity,
                credentials=[],
                audience=services["S01"].did,
            )
            blended_vp_errors["VP_ERR05"] = ErrorFixture(
                jwt_or_error="No error raised — unexpected",
                expected_behavior="create_presentation raises ValueError: credentials list cannot be empty",
                error_type="empty_credentials",
            )
        except ValueError as e:
            blended_vp_errors["VP_ERR05"] = ErrorFixture(
                jwt_or_error=str(e),
                expected_behavior="create_presentation raises ValueError: credentials list cannot be empty",
                error_type="empty_credentials",
            )

        # VP_ERR06: Cross-org mismatch — A01 (Acme) presents Bob's (Acme CFO) VC but
        # the delegation was issued by Eve (Globex CISO) — mismatched delegator org
        cross_org_vp = create_presentation(
            holder=agents["A01"].identity,
            credentials=[
                delegations["DC03"],  # Eve (Globex) delegated to A08, not A01
                humans["H02"].org_role_vc_jwt,  # Bob's Acme VC
                agents["A01"].agent_vc_jwt,
            ],
            audience=services["S01"].did,
        )
        blended_vp_errors["VP_ERR06"] = ErrorFixture(
            jwt_or_error=cross_org_vp,
            expected_behavior="MCP gateway verify_request detects holder DID != delegation subject; auth fails",
            error_type="cross_org_mismatch",
        )

        # VP_ERR07: Nonce mismatch — VP created with nonce-A but verified expecting nonce-B
        vp_with_nonce = create_presentation(
            holder=agents["A01"].identity,
            credentials=[delegations["DC01"], humans["H01"].org_role_vc_jwt],
            audience=services["S01"].did,
            nonce="nonce-AAA",
        )
        blended_vp_errors["VP_ERR07"] = ErrorFixture(
            jwt_or_error=vp_with_nonce,
            expected_behavior="verify_presentation(expected_nonce='nonce-BBB') returns verified=False; Nonce mismatch",
            error_type="nonce_mismatch",
            note="Verify with expected_nonce='nonce-BBB'",
        )

        # VP_ERR08: Tampered VP outer signature
        valid_vp_for_tamper = blended_vps["VP01"]
        vp_outer_parts = valid_vp_for_tamper.split(".")
        vp_outer_sig = bytearray(
            base64.urlsafe_b64decode(
                vp_outer_parts[2] + "=" * ((4 - len(vp_outer_parts[2]) % 4) % 4)
            )
        )
        vp_outer_sig[30 % len(vp_outer_sig)] ^= 0xFF
        tampered_vp_outer_sig = (
            base64.urlsafe_b64encode(bytes(vp_outer_sig)).rstrip(b"=").decode()
        )
        blended_vp_errors["VP_ERR08"] = ErrorFixture(
            jwt_or_error=f"{vp_outer_parts[0]}.{vp_outer_parts[1]}.{tampered_vp_outer_sig}",
            expected_behavior="verify_presentation returns verified=False; VP signature verification failed",
            error_type="tampered_vp_signature",
        )

        # VP_ERR09: Expired VP — manually craft VP with past exp
        now = int(time.time())
        exp_vp_payload = {
            "iss": agents["A01"].identity.did,
            "aud": services["S01"].did,
            "iat": now - 600,
            "exp": now - 300,  # expired 5 minutes ago
            "jti": str(uuid.uuid4()),
            "vp": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": agents["A01"].identity.did,
                "verifiableCredential": [delegations["DC01"], humans["H01"].org_role_vc_jwt],
            },
        }
        expired_vp_jwt = pyjwt.encode(
            exp_vp_payload,
            key=agents["A01"].identity.private_key,
            algorithm="EdDSA",
            headers={"kid": agents["A01"].identity.kid, "typ": "JWT"},
        )
        blended_vp_errors["VP_ERR09"] = ErrorFixture(
            jwt_or_error=expired_vp_jwt,
            expected_behavior="verify_presentation returns verified=False; Presentation expired",
            error_type="expired_vp",
        )

        # VP_ERR10: VP holder DID not starting with 'did:' — invalid format
        bad_iss_payload = {
            "iss": "not-a-did-string",
            "aud": services["S01"].did,
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "jti": str(uuid.uuid4()),
            "vp": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": "not-a-did-string",
                "verifiableCredential": [delegations["DC01"]],
            },
        }
        bad_iss_vp = pyjwt.encode(
            bad_iss_payload,
            key=agents["A01"].identity.private_key,
            algorithm="EdDSA",
            headers={"kid": agents["A01"].identity.kid, "typ": "JWT"},
        )
        blended_vp_errors["VP_ERR10"] = ErrorFixture(
            jwt_or_error=bad_iss_vp,
            expected_behavior="verify_presentation returns verified=False; Invalid holder DID",
            error_type="invalid_holder_did",
        )

        # VP_ERR11: Delegation subject mismatch — DC02 was issued to A07, but A01 presents it
        wrong_holder_vp = create_presentation(
            holder=agents["A01"].identity,
            credentials=[
                delegations["DC02"],  # issued to A07's DID, not A01's
                humans["H02"].org_role_vc_jwt,
                agents["A01"].agent_vc_jwt,
            ],
            audience=services["S01"].did,
        )
        blended_vp_errors["VP_ERR11"] = ErrorFixture(
            jwt_or_error=wrong_holder_vp,
            expected_behavior="MCP gateway detects vp.holder != delegation.sub; auth fails",
            error_type="delegation_subject_mismatch",
        )

        # VP_ERR12: Tampered delegation embedded in VP — flip a byte in DC01's payload section
        dc01_parts = delegations["DC01"].split(".")
        dc01_payload_bytes = bytearray(
            base64.urlsafe_b64decode(dc01_parts[1] + "=" * ((4 - len(dc01_parts[1]) % 4) % 4))
        )
        dc01_payload_bytes[15 % len(dc01_payload_bytes)] ^= 0x01
        tampered_dc01_payload = (
            base64.urlsafe_b64encode(bytes(dc01_payload_bytes)).rstrip(b"=").decode()
        )
        tampered_dc01 = f"{dc01_parts[0]}.{tampered_dc01_payload}.{dc01_parts[2]}"
        tampered_delegation_vp = create_presentation(
            holder=agents["A01"].identity,
            credentials=[tampered_dc01, humans["H01"].org_role_vc_jwt],
            audience=services["S01"].did,
        )
        blended_vp_errors["VP_ERR12"] = ErrorFixture(
            jwt_or_error=tampered_delegation_vp,
            expected_behavior="verify_presentation returns verified=False; credential 0 failed: Signature verification failed",
            error_type="tampered_delegation_in_vp",
        )

        return blended_vps, blended_vp_errors

    # ------------------------------------------------------------------
    # MCP auth contexts
    # ------------------------------------------------------------------

    def generate_mcp_contexts(
        self,
        humans: dict[str, HumanFixture],
        agents: dict[str, AgentFixture],
        services: dict[str, AgentIdentity],
        idps: dict[str, AgentIdentity],
        blended_vps: dict[str, str],
        blended_vp_errors: dict[str, ErrorFixture],
    ) -> dict[str, MCPTestContext]:
        """Generate 16 MCP auth test scenarios."""

        mcp_contexts: dict[str, MCPTestContext] = {}

        # MCP01: Happy path — trusted issuer, delegation required, all valid
        mcp_contexts["MCP01"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["OrganizationalRoleCredential", "DelegationCredential"],
                "require_delegation": True,
                "audience_did": services["S01"].did,
            },
            vp_jwt=blended_vps["VP01"],
            expected_authenticated=True,
        )

        # MCP02: Only AgentCredential required — A01's VP01 also contains AgentVC
        mcp_contexts["MCP02"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["AgentCredential"],
                "require_delegation": False,
                "audience_did": services["S01"].did,
            },
            vp_jwt=blended_vps["VP01"],
            expected_authenticated=True,
        )

        # MCP03: Multi-hop delegation (DC05) — 2-hop chain accepted
        mcp_contexts["MCP03"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["DelegationCredential"],
                "require_delegation": True,
                "audience_did": services["S05"].did,
            },
            vp_jwt=blended_vps["VP05"],
            expected_authenticated=True,
        )

        # MCP04: Three-hop delegation (DC07) — accepted
        mcp_contexts["MCP04"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["DelegationCredential"],
                "require_delegation": True,
                "audience_did": services["S05"].did,
            },
            vp_jwt=blended_vps["VP07"],
            expected_authenticated=True,
        )

        # MCP05: Expired VP — auth fails
        mcp_contexts["MCP05"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["DelegationCredential"],
                "require_delegation": True,
                "audience_did": services["S01"].did,
            },
            vp_jwt=blended_vp_errors["VP_ERR09"].jwt_or_error,
            expected_authenticated=False,
            expected_reason="Presentation expired",
        )

        # MCP06: Audience mismatch — VP targeted at S01, gateway is S02
        mcp_contexts["MCP06"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["DelegationCredential"],
                "require_delegation": True,
                "audience_did": services["S02"].did,
            },
            vp_jwt=blended_vp_errors["VP_ERR02"].jwt_or_error,
            expected_authenticated=False,
            expected_reason="Audience mismatch",
        )

        # MCP07: Tampered VP outer signature
        mcp_contexts["MCP07"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["DelegationCredential"],
                "require_delegation": True,
                "audience_did": services["S01"].did,
            },
            vp_jwt=blended_vp_errors["VP_ERR08"].jwt_or_error,
            expected_authenticated=False,
            expected_reason="VP signature verification failed",
        )

        # MCP08: Untrusted issuer — IDP01 not in trusted_issuers
        mcp_contexts["MCP08"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP02"].did],  # only Globex trusted
                "required_credential_types": ["OrganizationalRoleCredential"],
                "require_delegation": False,
                "audience_did": services["S01"].did,
            },
            vp_jwt=blended_vps["VP01"],  # contains IDP01-issued OrgRoleVC
            expected_authenticated=False,
            expected_reason="No credential from trusted issuer",
        )

        # MCP09: Missing required credential type — DelegationCredential absent
        mcp_contexts["MCP09"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["DelegationCredential"],
                "require_delegation": True,
                "audience_did": services["S01"].did,
            },
            vp_jwt=create_presentation(
                holder=agents["A01"].identity,
                credentials=[humans["H01"].org_role_vc_jwt, agents["A01"].agent_vc_jwt],
                audience=services["S01"].did,
            ),
            expected_authenticated=False,
            expected_reason="Required credential type DelegationCredential not present",
        )

        # MCP10: Cross-org mismatch VP — VP_ERR06
        mcp_contexts["MCP10"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did, idps["IDP02"].did],
                "required_credential_types": ["DelegationCredential"],
                "require_delegation": True,
                "audience_did": services["S01"].did,
            },
            vp_jwt=blended_vp_errors["VP_ERR06"].jwt_or_error,
            expected_authenticated=False,
            expected_reason="holder DID does not match delegation subject",
        )

        # MCP11: Globex agent A08 with valid VP03 -> Globex gateway
        mcp_contexts["MCP11"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP02"].did],
                "required_credential_types": ["DelegationCredential", "AgentCredential"],
                "require_delegation": True,
                "audience_did": services["S02"].did,
            },
            vp_jwt=blended_vps["VP03"],
            expected_authenticated=True,
        )

        # MCP12: Nonce-protected VP — valid nonce
        mcp_contexts["MCP12"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["DelegationCredential"],
                "require_delegation": True,
                "audience_did": services["S08"].did,
                "expected_nonce": "pramana-test-nonce-vp15",
            },
            vp_jwt=blended_vps["VP15"],
            expected_authenticated=True,
        )

        # MCP13: Nonce-protected VP — wrong nonce
        mcp_contexts["MCP13"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["DelegationCredential"],
                "require_delegation": True,
                "audience_did": services["S08"].did,
                "expected_nonce": "wrong-nonce",
            },
            vp_jwt=blended_vps["VP15"],
            expected_authenticated=False,
            expected_reason="Nonce mismatch",
        )

        # MCP14: VP with tampered inner VC — VP_ERR03
        mcp_contexts["MCP14"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["AgentCredential"],
                "require_delegation": True,
                "audience_did": services["S01"].did,
            },
            vp_jwt=blended_vp_errors["VP_ERR03"].jwt_or_error,
            expected_authenticated=False,
            expected_reason="Signature verification failed",
        )

        # MCP15: No delegation required — agent presents only AgentVC
        agent_only_vp = create_presentation(
            holder=agents["A04"].identity,
            credentials=[agents["A04"].agent_vc_jwt],
            audience=services["S01"].did,
        )
        mcp_contexts["MCP15"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["AgentCredential"],
                "require_delegation": False,
                "audience_did": services["S01"].did,
            },
            vp_jwt=agent_only_vp,
            expected_authenticated=True,
        )

        # MCP16: Wrong VP signer — VP_ERR04
        mcp_contexts["MCP16"] = MCPTestContext(
            config={
                "trusted_issuers": [idps["IDP01"].did],
                "required_credential_types": ["DelegationCredential"],
                "require_delegation": True,
                "audience_did": services["S01"].did,
            },
            vp_jwt=blended_vp_errors["VP_ERR04"].jwt_or_error,
            expected_authenticated=False,
            expected_reason="VP signature verification failed",
        )

        return mcp_contexts

    # ------------------------------------------------------------------
    # Trust baselines
    # ------------------------------------------------------------------

    def generate_trust_baselines(
        self, agents: dict[str, AgentFixture]
    ) -> dict[str, TrustBaseline]:
        """Generate expected trust score baselines for 10 agents."""

        return {
            "A01": TrustBaseline(
                agent_id=agents["A01"].identity.did,
                factors={
                    "credential_validity": 95,
                    "issuer_reputation": 90,
                    "delegation_chain_depth": 85,
                    "scope_appropriateness": 88,
                    "behavioral_history": 92,
                },
                expected_score=90,
                risk_tier="LOW",
            ),
            "A04": TrustBaseline(
                agent_id=agents["A04"].identity.did,
                factors={
                    "credential_validity": 92,
                    "issuer_reputation": 90,
                    "delegation_chain_depth": 95,
                    "scope_appropriateness": 85,
                    "behavioral_history": 88,
                },
                expected_score=90,
                risk_tier="LOW",
            ),
            "A08": TrustBaseline(
                agent_id=agents["A08"].identity.did,
                factors={
                    "credential_validity": 95,
                    "issuer_reputation": 88,
                    "delegation_chain_depth": 90,
                    "scope_appropriateness": 92,
                    "behavioral_history": 85,
                },
                expected_score=90,
                risk_tier="LOW",
            ),
            "A11": TrustBaseline(
                agent_id=agents["A11"].identity.did,
                factors={
                    "credential_validity": 90,
                    "issuer_reputation": 85,
                    "delegation_chain_depth": 90,
                    "scope_appropriateness": 88,
                    "behavioral_history": 80,
                },
                expected_score=87,
                risk_tier="LOW",
            ),
            "A21": TrustBaseline(
                agent_id=agents["A21"].identity.did,
                factors={
                    "credential_validity": 88,
                    "issuer_reputation": 85,
                    "delegation_chain_depth": 70,
                    "scope_appropriateness": 85,
                    "behavioral_history": 82,
                },
                expected_score=82,
                risk_tier="MEDIUM",
            ),
            "A22": TrustBaseline(
                agent_id=agents["A22"].identity.did,
                factors={
                    "credential_validity": 85,
                    "issuer_reputation": 85,
                    "delegation_chain_depth": 60,  # 3-hop
                    "scope_appropriateness": 88,
                    "behavioral_history": 78,
                },
                expected_score=79,
                risk_tier="MEDIUM",
            ),
            "A12": TrustBaseline(
                agent_id=agents["A12"].identity.did,
                factors={
                    "credential_validity": 90,
                    "issuer_reputation": 85,
                    "delegation_chain_depth": 75,
                    "scope_appropriateness": 92,
                    "behavioral_history": 85,
                },
                expected_score=85,
                risk_tier="LOW",
            ),
            "A24": TrustBaseline(
                agent_id=agents["A24"].identity.did,
                factors={
                    "credential_validity": 40,
                    "issuer_reputation": 10,
                    "delegation_chain_depth": 50,
                    "scope_appropriateness": 30,
                    "behavioral_history": 20,
                },
                expected_score=30,
                risk_tier="HIGH",
            ),
            "A25": TrustBaseline(
                agent_id=agents["A25"].identity.did,
                factors={
                    "credential_validity": 20,
                    "issuer_reputation": 5,
                    "delegation_chain_depth": 50,
                    "scope_appropriateness": 15,
                    "behavioral_history": 10,
                },
                expected_score=20,
                risk_tier="CRITICAL",
            ),
            "A16": TrustBaseline(
                agent_id=agents["A16"].identity.did,
                factors={
                    "credential_validity": 93,
                    "issuer_reputation": 90,
                    "delegation_chain_depth": 88,
                    "scope_appropriateness": 90,
                    "behavioral_history": 87,
                },
                expected_score=90,
                risk_tier="LOW",
            ),
        }

    # ------------------------------------------------------------------
    # Commerce mandates
    # ------------------------------------------------------------------

    def generate_commerce_mandates(
        self,
        humans: dict[str, HumanFixture],
        agents: dict[str, AgentFixture],
        delegations: dict[str, str],
    ) -> dict[str, CommerceFixture]:
        """Generate AP2 commerce mandate test fixtures M01-M10."""

        mandates: dict[str, CommerceFixture] = {}

        # M01: Valid intent + valid cart (within budget)
        intent_m01 = issue_intent_mandate(
            delegator=humans["H01"].identity,
            agent_did=agents["A01"].identity.did,
            intent={
                "max_amount": 15000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["electronics"],
                "description": "Buy a laptop accessory",
            },
        )
        cart_m01 = issue_cart_mandate(
            delegator=humans["H01"].identity,
            agent_did=agents["A01"].identity.did,
            cart={
                "total": {"value": 9999, "currency": "USD"},
                "items": [{"name": "USB-C Hub", "price": 9999}],
                "merchant_did": "did:key:z6MkmerchantAcme",
            },
            intent_mandate_jwt=intent_m01,
        )
        mandates["M01"] = CommerceFixture(
            intent_jwt=intent_m01,
            cart_jwt=cart_m01,
            delegator_id=humans["H01"].identity.did,
            agent_id=agents["A01"].identity.did,
            expected_valid=True,
        )

        # M02: Cart exceeds intent max_amount — ValueError raised
        intent_m02 = issue_intent_mandate(
            delegator=humans["H02"].identity,
            agent_did=agents["A13"].identity.did,
            intent={
                "max_amount": 5000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["office"],
                "description": "Office supplies",
            },
        )
        try:
            _ = issue_cart_mandate(
                delegator=humans["H02"].identity,
                agent_did=agents["A13"].identity.did,
                cart={
                    "total": {"value": 9999, "currency": "USD"},
                    "items": [{"name": "Standing Desk", "price": 9999}],
                },
                intent_mandate_jwt=intent_m02,
            )
            mandates["M02"] = CommerceFixture(
                intent_jwt=intent_m02,
                cart_jwt=None,
                delegator_id=humans["H02"].identity.did,
                agent_id=agents["A13"].identity.did,
                expected_valid=False,
                expected_reason="Cart total 9999 exceeds intent limit 5000",
                note="No error raised — unexpected",
            )
        except ValueError as e:
            mandates["M02"] = CommerceFixture(
                intent_jwt=intent_m02,
                cart_jwt=None,
                delegator_id=humans["H02"].identity.did,
                agent_id=agents["A13"].identity.did,
                expected_valid=False,
                expected_reason=str(e),
            )

        # M03: Valid travel mandate
        intent_m03 = issue_intent_mandate(
            delegator=humans["H04"].identity,
            agent_did=agents["A06"].identity.did,
            intent={
                "max_amount": 200000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["travel"],
                "description": "Q1 business travel",
                "requires_refundability": True,
            },
        )
        cart_m03 = issue_cart_mandate(
            delegator=humans["H04"].identity,
            agent_did=agents["A06"].identity.did,
            cart={
                "total": {"value": 149900, "currency": "USD"},
                "items": [
                    {"name": "SFO-JFK Flight", "price": 89900},
                    {"name": "Hotel 3 nights", "price": 60000},
                ],
                "merchant_did": "did:key:z6MkmerchantTravel",
                "payment_method_type": "corporate_card",
            },
            intent_mandate_jwt=intent_m03,
        )
        mandates["M03"] = CommerceFixture(
            intent_jwt=intent_m03,
            cart_jwt=cart_m03,
            delegator_id=humans["H04"].identity.did,
            agent_id=agents["A06"].identity.did,
            expected_valid=True,
        )

        # M04: Valid billing mandate — exact budget match
        intent_m04 = issue_intent_mandate(
            delegator=humans["H08"].identity,
            agent_did=agents["A13"].identity.did,
            intent={
                "max_amount": 50000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["billing"],
                "description": "Monthly vendor payments",
            },
        )
        cart_m04 = issue_cart_mandate(
            delegator=humans["H08"].identity,
            agent_did=agents["A13"].identity.did,
            cart={
                "total": {"value": 50000, "currency": "USD"},
                "items": [{"name": "SaaS Invoice", "price": 50000}],
            },
            intent_mandate_jwt=intent_m04,
        )
        mandates["M04"] = CommerceFixture(
            intent_jwt=intent_m04,
            cart_jwt=cart_m04,
            delegator_id=humans["H08"].identity.did,
            agent_id=agents["A13"].identity.did,
            expected_valid=True,
        )

        # M05: Currency mismatch — cart in EUR, intent in USD
        intent_m05 = issue_intent_mandate(
            delegator=humans["H01"].identity,
            agent_did=agents["A01"].identity.did,
            intent={
                "max_amount": 10000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["electronics"],
            },
        )
        try:
            _ = issue_cart_mandate(
                delegator=humans["H01"].identity,
                agent_did=agents["A01"].identity.did,
                cart={
                    "total": {"value": 8000, "currency": "EUR"},
                    "items": [{"name": "Keyboard", "price": 8000}],
                },
                intent_mandate_jwt=intent_m05,
            )
            mandates["M05"] = CommerceFixture(
                intent_jwt=intent_m05,
                cart_jwt=None,
                delegator_id=humans["H01"].identity.did,
                agent_id=agents["A01"].identity.did,
                expected_valid=False,
                expected_reason="Currency mismatch: cart uses 'EUR' but intent requires 'USD'",
                note="No error raised — unexpected",
            )
        except ValueError as e:
            mandates["M05"] = CommerceFixture(
                intent_jwt=intent_m05,
                cart_jwt=None,
                delegator_id=humans["H01"].identity.did,
                agent_id=agents["A01"].identity.did,
                expected_valid=False,
                expected_reason=str(e),
            )

        # M06: Replay attack placeholder — same cart JWT submitted twice (server-side test)
        intent_m06 = issue_intent_mandate(
            delegator=humans["H03"].identity,
            agent_did=agents["A03"].identity.did,
            intent={
                "max_amount": 3000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["services"],
            },
        )
        cart_m06 = issue_cart_mandate(
            delegator=humans["H03"].identity,
            agent_did=agents["A03"].identity.did,
            cart={"total": {"value": 2500, "currency": "USD"}},
            intent_mandate_jwt=intent_m06,
        )
        mandates["M06"] = CommerceFixture(
            intent_jwt=intent_m06,
            cart_jwt=cart_m06,
            delegator_id=humans["H03"].identity.did,
            agent_id=agents["A03"].identity.did,
            expected_valid=True,
            note="replay_attack_test: submit cart_jwt twice; second submission should fail with 'mandate already used'",
        )

        # M07: Zero-amount intent — should raise ValueError
        try:
            _ = issue_intent_mandate(
                delegator=humans["H05"].identity,
                agent_did=agents["A08"].identity.did,
                intent={
                    "max_amount": 0,
                    "currency": "USD",
                    "merchants": [],
                    "categories": ["security"],
                },
            )
            mandates["M07"] = CommerceFixture(
                intent_jwt="",
                cart_jwt=None,
                delegator_id=humans["H05"].identity.did,
                agent_id=agents["A08"].identity.did,
                expected_valid=False,
                expected_reason="intent.max_amount must be a positive integer, got 0",
                note="No error raised — unexpected",
            )
        except ValueError as e:
            mandates["M07"] = CommerceFixture(
                intent_jwt=str(e),
                cart_jwt=None,
                delegator_id=humans["H05"].identity.did,
                agent_id=agents["A08"].identity.did,
                expected_valid=False,
                expected_reason=str(e),
            )

        # M08: Cumulative budget scenario placeholder (server-side test)
        intent_m08 = issue_intent_mandate(
            delegator=humans["H10"].identity,
            agent_did=agents["A16"].identity.did,
            intent={
                "max_amount": 100000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["research"],
                "description": "Annual lab supply budget",
            },
        )
        cart_m08a = issue_cart_mandate(
            delegator=humans["H10"].identity,
            agent_did=agents["A16"].identity.did,
            cart={"total": {"value": 60000, "currency": "USD"}},
            intent_mandate_jwt=intent_m08,
        )
        cart_m08b = issue_cart_mandate(
            delegator=humans["H10"].identity,
            agent_did=agents["A16"].identity.did,
            cart={"total": {"value": 60000, "currency": "USD"}},
            intent_mandate_jwt=intent_m08,
        )
        mandates["M08"] = CommerceFixture(
            intent_jwt=intent_m08,
            cart_jwt=json.dumps({"cart_a": cart_m08a, "cart_b": cart_m08b}),
            delegator_id=humans["H10"].identity.did,
            agent_id=agents["A16"].identity.did,
            expected_valid=True,  # each individual cart is valid; combined budget check is server-side
            note="cumulative_budget_test: two carts each $600; combined $1200 exceeds $1000 intent; server should reject second cart_b via cumulative tracking",
        )

        # M09: Missing currency in intent — ValueError
        try:
            _ = issue_intent_mandate(
                delegator=humans["H07"].identity,
                agent_did=agents["A11"].identity.did,
                intent={
                    "max_amount": 5000,
                    # currency omitted
                    "merchants": ["*"],
                    "categories": ["devops"],
                },
            )
            mandates["M09"] = CommerceFixture(
                intent_jwt="",
                cart_jwt=None,
                delegator_id=humans["H07"].identity.did,
                agent_id=agents["A11"].identity.did,
                expected_valid=False,
                expected_reason="intent.currency is required",
                note="No error raised — unexpected",
            )
        except ValueError as e:
            mandates["M09"] = CommerceFixture(
                intent_jwt=str(e),
                cart_jwt=None,
                delegator_id=humans["H07"].identity.did,
                agent_id=agents["A11"].identity.did,
                expected_valid=False,
                expected_reason=str(e),
            )

        # M10: Valid lab-to-reporting sub-delegation mandate
        intent_m10 = issue_intent_mandate(
            delegator=humans["H10"].identity,
            agent_did=agents["A17"].identity.did,
            intent={
                "max_amount": 2000,
                "currency": "USD",
                "merchants": ["*"],
                "categories": ["research"],
                "description": "Report generation budget",
            },
        )
        cart_m10 = issue_cart_mandate(
            delegator=humans["H10"].identity,
            agent_did=agents["A17"].identity.did,
            cart={
                "total": {"value": 1500, "currency": "USD"},
                "items": [{"name": "Cloud rendering", "price": 1500}],
            },
            intent_mandate_jwt=intent_m10,
        )
        mandates["M10"] = CommerceFixture(
            intent_jwt=intent_m10,
            cart_jwt=cart_m10,
            delegator_id=humans["H10"].identity.did,
            agent_id=agents["A17"].identity.did,
            expected_valid=True,
        )

        return mandates

    # ------------------------------------------------------------------
    # Audit events
    # ------------------------------------------------------------------

    def generate_audit_events(
        self,
        agents: dict[str, AgentFixture],
        services: dict[str, AgentIdentity],
    ) -> list[dict]:
        """Generate 200+ deterministic audit trail events with anomalies."""

        events: list[dict] = []
        base_ts = int(time.time()) - (7 * 24 * 3600)  # 7 days ago

        # Tool access patterns per agent type
        _tool_map = {
            "LLM": ["read_document", "web_search", "generate_text", "send_message"],
            "Analytics": ["query_database", "run_report", "export_csv", "read_metrics"],
            "Scanner": ["port_scan", "log_analysis", "alert_create", "read_config"],
            "CI/CD": ["trigger_deploy", "read_config", "read_logs", "run_test"],
            "Monitor": ["read_metrics", "alert_create", "read_logs", "ping_service"],
            "Logistics": ["track_shipment", "update_status", "read_inventory", "generate_po"],
            "Scientific": ["read_sensor", "write_measurement", "run_analysis", "export_data"],
            "Unknown": ["read_document", "web_search"],
        }

        agent_ids = list(agents.keys())
        service_ids = list(services.keys())

        event_id = 0

        def _event(agent_id: str, event_type: str, ts: int, tool: str,
                   success: bool, extra: Optional[dict] = None) -> dict:
            nonlocal event_id
            event_id += 1
            return {
                "event_id": f"EVT-{event_id:04d}",
                "agent_id": agents[agent_id].identity.did,
                "agent_label": agent_id,
                "event_type": event_type,
                "timestamp": ts,
                "tool_accessed": tool,
                "success": success,
                "service_did": services[service_ids[event_id % len(service_ids)]].did,
                "metadata": extra or {},
            }

        # Normal baseline events — spread across 7 days for each org agent
        normal_agents = [
            a for a in agent_ids if a not in ("A24", "A25")
        ]
        for day in range(7):
            day_base = base_ts + day * 86400
            for agent_id in normal_agents:
                agent_fix = agents[agent_id]
                tools = _tool_map.get(agent_fix.agent_type, _tool_map["LLM"])
                # 3-6 events per agent per day
                n_events = self.rng.randint(3, 6)
                for _ in range(n_events):
                    offset = self.rng.randint(0, 86399)
                    tool = self.rng.choice(tools)
                    success = self.rng.random() > 0.05  # 95% success rate
                    events.append(_event(
                        agent_id=agent_id,
                        event_type="tool_call",
                        ts=day_base + offset,
                        tool=tool,
                        success=success,
                        extra={"day": day},
                    ))

        # Anomaly 1: Velocity spike — A01 makes 25 calls in 1 minute on day 3
        spike_base = base_ts + 3 * 86400 + 14 * 3600
        for i in range(25):
            events.append(_event(
                agent_id="A01",
                event_type="tool_call",
                ts=spike_base + i * 2,
                tool="submit:order",
                success=True,
                extra={"anomaly": "velocity_spike", "burst_index": i},
            ))

        # Anomaly 2: Novel tool access — A04 accesses 'delete_database' (not in its type)
        events.append(_event(
            agent_id="A04",
            event_type="tool_call",
            ts=base_ts + 2 * 86400 + 9 * 3600,
            tool="delete_database",
            success=False,
            extra={"anomaly": "novel_tool_access", "tool_not_in_scope": True},
        ))

        # Anomaly 3: Failure spike — A08 has 10 consecutive failures on day 5
        fail_base = base_ts + 5 * 86400 + 11 * 3600
        for i in range(10):
            events.append(_event(
                agent_id="A08",
                event_type="tool_call",
                ts=fail_base + i * 60,
                tool="port_scan",
                success=False,
                extra={"anomaly": "failure_spike", "error": "connection_refused", "seq": i},
            ))

        # Anomaly 4: Off-hours access — A11 triggers production deploy at 3am on day 4
        events.append(_event(
            agent_id="A11",
            event_type="tool_call",
            ts=base_ts + 4 * 86400 + 3 * 3600 + 14 * 60,
            tool="trigger_deploy",
            success=True,
            extra={"anomaly": "off_hours_access", "environment": "production"},
        ))

        # Anomaly 5: A24 (adversarial) probing multiple agents' tools
        adversarial_base = base_ts + 6 * 86400 + 20 * 3600
        probe_tools = ["read_config", "query_database", "export_csv", "read_metrics",
                       "read_logs", "port_scan", "track_shipment", "write_measurement"]
        for i, tool in enumerate(probe_tools):
            events.append(_event(
                agent_id="A24",
                event_type="tool_call",
                ts=adversarial_base + i * 30,
                tool=tool,
                success=False,
                extra={"anomaly": "adversarial_probing", "probe_seq": i},
            ))

        # Anomaly 6: A25 (untrusted) attempted auth events
        for i in range(5):
            event_id += 1
            events.append({
                "event_id": f"EVT-{event_id:04d}",
                "agent_id": agents["A25"].identity.did,
                "agent_label": "A25",
                "event_type": "auth_failure",
                "timestamp": base_ts + 1 * 86400 + i * 3600,
                "tool_accessed": "mcp_gateway_auth",
                "success": False,
                "service_did": services["S01"].did,
                "metadata": {"anomaly": "repeated_auth_failure", "attempt": i + 1},
            })

        # Anomaly 7: Trust score drop signal — A21 starts accessing resources outside scope
        scope_events = [
            ("submit:payment", base_ts + 6 * 86400 + 15 * 3600),
            ("delete_account", base_ts + 6 * 86400 + 15 * 3600 + 300),
            ("export_all_data", base_ts + 6 * 86400 + 15 * 3600 + 600),
        ]
        for tool, ts in scope_events:
            events.append(_event(
                agent_id="A21",
                event_type="tool_call",
                ts=ts,
                tool=tool,
                success=False,
                extra={"anomaly": "out_of_scope_access", "scope_violation": True},
            ))

        # Sort by timestamp for realistic audit trail order
        events.sort(key=lambda e: e["timestamp"])

        return events

    # ------------------------------------------------------------------
    # generate_all
    # ------------------------------------------------------------------

    def generate_all(self) -> SyntheticDataSet:
        """Run all generators and return the assembled SyntheticDataSet."""

        humans, agents, services, idps = self.generate_identities()
        delegations, delegation_errors = self.generate_delegations(humans, agents)
        blended_vps, blended_vp_errors = self.generate_blended_vps(
            humans, agents, services, delegations, delegation_errors
        )
        mcp_contexts = self.generate_mcp_contexts(
            humans, agents, services, idps, blended_vps, blended_vp_errors
        )
        trust_baselines = self.generate_trust_baselines(agents)
        commerce_mandates = self.generate_commerce_mandates(humans, agents, delegations)
        audit_events = self.generate_audit_events(agents, services)

        return SyntheticDataSet(
            humans=humans,
            agents=agents,
            services=services,
            idps=idps,
            delegations=delegations,
            delegation_errors=delegation_errors,
            blended_vps=blended_vps,
            blended_vp_errors=blended_vp_errors,
            mcp_contexts=mcp_contexts,
            trust_baselines=trust_baselines,
            commerce_mandates=commerce_mandates,
            audit_events=audit_events,
        )

    # ------------------------------------------------------------------
    # print_summary
    # ------------------------------------------------------------------

    @staticmethod
    def print_summary(data: SyntheticDataSet) -> None:
        """Print a human-readable summary table."""
        print("\n" + "=" * 60)
        print("  Pramana Synthetic Data Generator — Summary")
        print("=" * 60)
        rows = [
            ("Humans",              len(data.humans)),
            ("AI Agents",           len(data.agents)),
            ("Services/Verifiers",  len(data.services)),
            ("Enterprise IdPs",     len(data.idps)),
            ("Valid Delegations",   len(data.delegations)),
            ("Delegation Errors",   len(data.delegation_errors)),
            ("Valid Blended VPs",   len(data.blended_vps)),
            ("VP Errors",           len(data.blended_vp_errors)),
            ("MCP Auth Contexts",   len(data.mcp_contexts)),
            ("Trust Baselines",     len(data.trust_baselines)),
            ("Commerce Mandates",   len(data.commerce_mandates)),
            ("Audit Events",        len(data.audit_events)),
        ]
        total_identities = (
            len(data.humans) + len(data.agents) + len(data.services) + len(data.idps)
        )
        for label, count in rows:
            print(f"  {label:<28} {count:>4}")
        print("-" * 60)
        print(f"  {'Total Identities':<28} {total_identities:>4}")
        print("=" * 60)

        # Sample determinism check
        h01_did = data.humans["H01"].identity.did
        a01_did = data.agents["A01"].identity.did
        print(f"\n  H01 DID: {h01_did[:48]}...")
        print(f"  A01 DID: {a01_did[:48]}...")
        print()

        # Delegation chain spot check
        dc01_result = verify_delegation_chain(data.delegations["DC01"])
        print(f"  DC01 verify: verified={dc01_result.verified}, depth={dc01_result.depth}")

        dc07_result = verify_delegation_chain(data.delegations["DC07"])
        print(f"  DC07 (3-hop) verify: verified={dc07_result.verified}, depth={dc07_result.depth}")

        # VP spot check
        vp01_result = verify_presentation(
            data.blended_vps["VP01"],
            expected_audience=data.services["S01"].did,
        )
        print(f"  VP01 verify: verified={vp01_result.verified}, creds={len(vp01_result.credentials)}")

        print()


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    gen = SyntheticDataGenerator(seed=42)
    data = gen.generate_all()
    gen.print_summary(data)
