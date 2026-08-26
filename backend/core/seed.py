from __future__ import annotations

import logging
import math
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional

from sqlalchemy import func, select, text

from core import did as did_core
from core.audit import write_audit
from core.crypto import encrypt_text
from core.db import db_session
from core.settings import settings
from core.status_list import get_or_create_default_list, allocate_index, set_revoked
from core.tenancy import ensure_tenant
from core.vc import issue_vc_jwt
from models import Agent, AuditEvent, Credential, Key, MandateSpend, TrustEvent

logger = logging.getLogger(__name__)

# Seed with a fixed random seed for reproducible patterns (but varied enough to look real)
_RNG = random.Random(42)


@dataclass
class SeedResult:
    agents: int = 0
    credentials: int = 0
    credentials_revoked: int = 0
    delegations: int = 0
    mandate_intents: int = 0
    mandate_spends: int = 0
    audit_events: int = 0
    trust_events: int = 0


# ---------------------------------------------------------------------------
# Agent roster: (name, role, org, spiffe_id_or_None)
# ---------------------------------------------------------------------------

STANDARD_AGENTS: list[tuple[str, str, str, Optional[str]]] = [
    # Org 1: Acme Corp
    ("acme-corp-root-ca",       "root-issuer",  "acme",      None),
    ("acme-corp-hr",            "issuer",        "acme",      None),
    ("acme-procurement-alpha",  "worker",        "acme",      "spiffe://acme.corp/ns/production/sa/procurement-alpha"),
    ("acme-procurement-beta",   "worker",        "acme",      "spiffe://acme.corp/ns/production/sa/procurement-beta"),
    ("acme-procurement-sub",    "worker",        "acme",      None),
    ("acme-customer-service",   "worker",        "acme",      "spiffe://acme.corp/ns/production/sa/customer-service"),
    ("acme-analytics-bot",      "worker",        "acme",      None),
    # Org 2: GlobalBank
    ("globalbank-root-ca",      "root-issuer",  "globalbank", None),
    ("globalbank-kyc-issuer",   "issuer",        "globalbank", None),
    ("globalbank-trading-bot",  "worker",        "globalbank", "spiffe://globalbank.com/ns/trading/sa/trading-bot"),
    ("globalbank-compliance-bot","worker",       "globalbank", "spiffe://globalbank.com/ns/compliance/sa/compliance-bot"),
    ("globalbank-audit-agent",  "worker",        "globalbank", None),
    # Org 3: HealthPlus
    ("healthplus-root-ca",      "root-issuer",  "healthplus", None),
    ("healthplus-compliance",   "issuer",        "healthplus", None),
    ("healthplus-diagnosis-ai", "worker",        "healthplus", "spiffe://healthplus.ai/ns/clinical/sa/diagnosis-ai"),
    ("healthplus-records-agent","worker",        "healthplus", None),
    # EU AI Act compliant agents
    ("euai-compliance-issuer",  "issuer",        "euai",       None),
    ("euai-high-risk-agent",    "worker",        "euai",       "spiffe://euai.corp/ns/regulated/sa/high-risk-agent"),
    ("euai-limited-risk-agent", "worker",        "euai",       None),
    # Merchants
    ("nike-merchant",           "merchant",      "merchants",  None),
    ("aws-cloud-merchant",      "merchant",      "merchants",  None),
    ("office-depot-merchant",   "merchant",      "merchants",  None),
    ("grocery-mart-merchant",   "merchant",      "merchants",  None),
    ("saas-vendor-merchant",    "merchant",      "merchants",  None),
    # Misc
    ("external-auditor",        "auditor",       "external",   None),
    ("partner-api-agent",       "partner",       "external",   None),
    ("temp-contractor-bot",     "contractor",    "external",   None),
    ("decommissioned-agent",    "revoked",       "external",   None),
    ("rogue-test-agent",        "adversarial",   "external",   None),
    ("monitoring-agent",        "monitor",       "internal",   None),
    ("ci-cd-deploy-bot",        "automation",    "internal",   "spiffe://internal.corp/ns/cicd/sa/deploy-bot"),
    ("data-pipeline-agent",     "automation",    "internal",   None),
    ("backup-service-agent",    "automation",    "internal",   None),
]

MINIMAL_AGENTS: list[tuple[str, str, str, Optional[str]]] = [
    ("acme-corp-root-ca",      "root-issuer", "acme",      None),
    ("acme-corp-hr",           "issuer",       "acme",      None),
    ("acme-procurement-alpha", "worker",       "acme",      "spiffe://acme.corp/ns/production/sa/procurement-alpha"),
    ("acme-procurement-beta",  "worker",       "acme",      None),
    ("nike-merchant",          "merchant",     "merchants", None),
    ("decommissioned-agent",   "revoked",      "external",  None),
    ("rogue-test-agent",       "adversarial",  "external",  None),
    ("monitoring-agent",       "monitor",      "internal",  None),
]

# ---------------------------------------------------------------------------
# Credential plan
# ---------------------------------------------------------------------------

CREDENTIAL_PLAN: list[tuple[str, str, str, dict]] = [
    # Acme Corp
    ("acme-corp-root-ca", "acme-corp-hr", "OrganizationalRoleCredential",
     {"role": "hr-administrator", "org": "acme-corp", "permissions": ["issue_credentials"]}),
    ("acme-corp-hr", "acme-procurement-alpha", "AgentCredential",
     {"role": "procurement-agent", "department": "supply-chain", "clearance": "high"}),
    ("acme-corp-hr", "acme-procurement-beta", "AgentCredential",
     {"role": "procurement-agent", "department": "supply-chain", "clearance": "standard"}),
    ("acme-corp-hr", "acme-customer-service", "CapabilityCredential",
     {"capability": "customer_support", "channels": ["chat", "email"]}),
    ("acme-corp-hr", "acme-analytics-bot", "CapabilityCredential",
     {"capability": "data_analysis", "datasets": ["sales", "inventory"]}),
    # GlobalBank
    ("globalbank-root-ca", "globalbank-kyc-issuer", "OrganizationalRoleCredential",
     {"role": "kyc-authority", "org": "globalbank", "jurisdiction": "US"}),
    ("globalbank-kyc-issuer", "globalbank-trading-bot", "AgentCredential",
     {"role": "trading-agent", "asset_classes": ["equities", "bonds"],
      "attestation_selectors": [{"type": "k8s:ns", "value": "trading"},
                                  {"type": "spiffe:td", "value": "globalbank.com"}]}),
    ("globalbank-kyc-issuer", "globalbank-compliance-bot", "ComplianceCredential",
     {"standard": "SOC2", "scope": "type-ii", "certified": True,
      "controls": ["CC6.1", "CC6.2", "CC6.6", "CC7.1"]}),
    ("globalbank-kyc-issuer", "globalbank-audit-agent", "CapabilityCredential",
     {"capability": "audit_read", "scope": "all-transactions"}),
    # HealthPlus
    ("healthplus-root-ca", "healthplus-compliance", "OrganizationalRoleCredential",
     {"role": "compliance-officer", "org": "healthplus", "frameworks": ["HIPAA", "EU AI Act"]}),
    ("healthplus-compliance", "healthplus-diagnosis-ai", "ComplianceCredential",
     {"standard": "HIPAA", "scope": "phi-read", "max_records_per_day": 50,
      "attestation_selectors": [{"type": "spiffe:td", "value": "healthplus.ai"},
                                  {"type": "k8s:ns", "value": "clinical"}]}),
    ("healthplus-compliance", "healthplus-records-agent", "AgentCredential",
     {"role": "records-access", "department": "medical-records"}),
    # EU AI Act credentials
    ("euai-compliance-issuer", "euai-high-risk-agent", "ComplianceCredential",
     {"standard": "EU AI Act", "risk_level": "high", "article": "6",
      "human_oversight_required": True, "audit_trail_required": True,
      "transparency_obligation": True, "technical_documentation": "available",
      "attestation_selectors": [{"type": "spiffe:td", "value": "euai.corp"},
                                  {"type": "k8s:ns", "value": "regulated"}]}),
    ("euai-compliance-issuer", "euai-limited-risk-agent", "ComplianceCredential",
     {"standard": "EU AI Act", "risk_level": "limited", "article": "52",
      "transparency_obligation": True}),
    ("euai-compliance-issuer", "euai-compliance-issuer", "ComplianceCredential",
     {"standard": "ISO 42001", "scope": "ai-management-system", "certified": True}),
    # Merchant credentials
    ("acme-corp-root-ca", "nike-merchant", "MerchantCredential",
     {"categories": ["footwear", "apparel"], "region": "global", "accepts": ["CARD"]}),
    ("acme-corp-root-ca", "aws-cloud-merchant", "MerchantCredential",
     {"categories": ["cloud", "compute"], "region": "global", "accepts": ["CARD", "WIRE"]}),
    ("acme-corp-root-ca", "office-depot-merchant", "MerchantCredential",
     {"categories": ["office-supplies"], "region": "US", "accepts": ["CARD"]}),
    ("acme-corp-root-ca", "grocery-mart-merchant", "MerchantCredential",
     {"categories": ["groceries"], "region": "US", "accepts": ["CARD"]}),
    ("acme-corp-root-ca", "saas-vendor-merchant", "MerchantCredential",
     {"categories": ["software", "saas"], "region": "global", "accepts": ["CARD", "WIRE"]}),
    # Delegation credentials
    ("acme-corp-root-ca", "acme-corp-hr", "DelegationCredential",
     {"delegatedBy": "ISSUER_DID",
      "delegationScope": {"actions": ["purchase", "approve"], "max_amount": 50000,
                          "currency": "USD", "merchants": ["*"]},
      "delegationDepth": 0, "maxDelegationDepth": 3}),
    ("acme-corp-hr", "acme-procurement-alpha", "DelegationCredential",
     {"delegatedBy": "ISSUER_DID",
      "delegationScope": {"actions": ["purchase"], "max_amount": 5000,
                          "currency": "USD", "merchants": ["*"],
                          "attestation_selectors": [{"type": "spiffe:td", "value": "acme.corp"}]},
      "delegationDepth": 1, "maxDelegationDepth": 2}),
    ("acme-procurement-alpha", "acme-procurement-sub", "DelegationCredential",
     {"delegatedBy": "ISSUER_DID",
      "delegationScope": {"actions": ["purchase"], "max_amount": 500,
                          "currency": "USD", "merchants": ["*"]},
      "delegationDepth": 2, "maxDelegationDepth": 1}),
    ("acme-corp-hr", "acme-procurement-beta", "DelegationCredential",
     {"delegatedBy": "ISSUER_DID",
      "delegationScope": {"actions": ["purchase"], "max_amount": 1000,
                          "currency": "USD", "merchants": ["*"]},
      "delegationDepth": 1, "maxDelegationDepth": 1}),
]

BULK_AGENT_CRED_SUBJECTS: list[tuple[str, str]] = [
    ("acme-procurement-sub",    "acme-corp-hr"),
    ("globalbank-root-ca",      "globalbank-root-ca"),
    ("healthplus-root-ca",      "healthplus-root-ca"),
    ("external-auditor",        "acme-corp-root-ca"),
    ("partner-api-agent",       "acme-corp-root-ca"),
    ("temp-contractor-bot",     "acme-corp-root-ca"),
    ("decommissioned-agent",    "acme-corp-root-ca"),
    ("rogue-test-agent",        "acme-corp-root-ca"),
    ("monitoring-agent",        "acme-corp-root-ca"),
    ("ci-cd-deploy-bot",        "acme-corp-root-ca"),
    ("data-pipeline-agent",     "acme-corp-root-ca"),
    ("backup-service-agent",    "acme-corp-root-ca"),
    ("euai-compliance-issuer",  "euai-compliance-issuer"),
]

# ---------------------------------------------------------------------------
# Trust event config: (agent_name, base_score, trajectory, volatility)
# trajectory: "rising" | "stable" | "declining" | "crashed"
# ---------------------------------------------------------------------------

TRUST_AGENT_PROFILES: list[tuple[str, float, str, float]] = [
    ("acme-procurement-alpha",  85.0, "stable",    4.0),
    ("acme-procurement-beta",   70.0, "declining", 8.0),
    ("acme-customer-service",   90.0, "rising",    3.0),
    ("globalbank-trading-bot",  88.0, "stable",    3.0),
    ("globalbank-compliance-bot", 92.0, "rising",  2.0),
    ("healthplus-diagnosis-ai", 78.0, "stable",    5.0),
    ("euai-high-risk-agent",    75.0, "stable",    6.0),
    ("rogue-test-agent",        30.0, "crashed",   15.0),
    ("decommissioned-agent",    40.0, "declining", 10.0),
    ("monitoring-agent",        95.0, "rising",    2.0),
    ("ci-cd-deploy-bot",        82.0, "stable",    4.0),
    ("temp-contractor-bot",     55.0, "declining", 12.0),
]

EVENT_TYPE_BY_TRAJECTORY = {
    "rising":   ["verification_success", "delegation_issued", "mandate_verified"],
    "stable":   ["verification_success", "verification_success", "verification_failure"],
    "declining": ["verification_failure", "scope_violation_attempt", "verification_success"],
    "crashed":  ["verification_failure", "scope_violation_attempt", "credential_revoked"],
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _create_agent(tenant_id: str, name: str, spiffe_id: Optional[str] = None) -> tuple[Agent, Key]:
    agent_id = uuid.uuid4()
    did = did_core.create_did(agent_id)
    private_pem, public_jwk, _ = did_core.generate_ed25519_keypair()
    kid = f"{did}#key-1"
    agent = Agent(id=agent_id, name=name, did=did, tenant_id=tenant_id, spiffe_id=spiffe_id)
    key = Key(
        agent_id=agent_id,
        tenant_id=tenant_id,
        kid=kid,
        public_jwk=public_jwk,
        private_key_enc=encrypt_text(private_pem),
    )
    with db_session() as db:
        ensure_tenant(db, tenant_id)
        db.add(agent)
        db.add(key)
        db.commit()
        db.refresh(agent)
        db.refresh(key)
    return agent, key


def _issue_credential(
    tenant_id: str,
    issuer: Agent,
    subject_did: str,
    credential_type: str,
    extra_claims: dict,
    ttl_seconds: int = 86400 * 365,
) -> tuple[Credential, str]:
    sl = get_or_create_default_list(tenant_id=tenant_id)
    index = allocate_index(sl.id)
    status_list_url = (
        f"{settings.tesht_scheme}://{did_core.domain_decoded()}/v1/status/{sl.id}"
    )
    token, jti, iat, exp = issue_vc_jwt(
        issuer_agent_id=issuer.id,
        subject_did=subject_did,
        credential_type=credential_type,
        status_list_url=status_list_url,
        status_list_index=index,
        ttl_seconds=ttl_seconds,
        extra_claims=extra_claims,
    )
    cred = Credential(
        tenant_id=tenant_id,
        issuer_agent_id=issuer.id,
        subject_did=subject_did,
        credential_type=credential_type,
        jti=jti,
        jwt=token,
        status_list_id=sl.id,
        status_list_index=index,
        issued_at=datetime.utcfromtimestamp(iat),
        expires_at=(datetime.utcfromtimestamp(exp) if exp else None),
    )
    with db_session() as db:
        db.add(cred)
        db.commit()
        db.refresh(cred)
    return cred, token


def _resolve_did_placeholders(claims: dict, agents_map: dict[str, Agent], issuer_name: str) -> dict:
    issuer_did = agents_map[issuer_name].did if issuer_name in agents_map else "unknown"
    result: dict = {}
    for k, v in claims.items():
        if v == "ISSUER_DID":
            result[k] = issuer_did
        elif isinstance(v, dict):
            result[k] = _resolve_did_placeholders(v, agents_map, issuer_name)
        else:
            result[k] = v
    return result


def _seed_delegation_registry(
    tenant_id: str,
    agents_map: dict[str, Agent],
    result: SeedResult,
) -> None:
    root_jti = f"urn:uuid:seed-del-root-{uuid.uuid4().hex[:8]}"
    child1_jti = f"urn:uuid:seed-del-child1-{uuid.uuid4().hex[:8]}"
    child2_jti = f"urn:uuid:seed-del-child2-{uuid.uuid4().hex[:8]}"
    gc_jti = f"urn:uuid:seed-del-gc-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)

    rows = [
        (root_jti,  tenant_id, agents_map["acme-corp-root-ca"].did,      agents_map["acme-corp-hr"].did,           None,       now),
        (child1_jti, tenant_id, agents_map["acme-corp-hr"].did,           agents_map["acme-procurement-alpha"].did, root_jti,   now),
        (child2_jti, tenant_id, agents_map["acme-corp-hr"].did,           agents_map["acme-procurement-beta"].did,  root_jti,   now),
        (gc_jti,    tenant_id, agents_map["acme-procurement-alpha"].did,  agents_map["acme-procurement-sub"].did,   child1_jti, now),
    ]

    with db_session() as db:
        for row in rows:
            jti, tid, iss, sub, parent, cat = row
            db.execute(
                text(
                    "INSERT INTO delegation_registry "
                    "(jti, tenant_id, issuer_did, subject_did, parent_jti, "
                    "status_list_id, status_list_index, created_at, revoked_at) "
                    "VALUES (:jti, :tid, :iss, :sub, :parent, NULL, NULL, :cat, NULL)"
                ),
                {"jti": jti, "tid": tid, "iss": iss, "sub": sub, "parent": parent, "cat": cat},
            )
        db.commit()

    for row in rows:
        jti, tid, iss, sub, parent, _ = row
        write_audit(
            tenant_id=tenant_id,
            event_type="delegation.registered",
            actor="seed",
            resource_type="delegation",
            resource_id=jti,
            payload={"issuer_did": iss, "subject_did": sub, "parent_jti": parent},
        )

    result.delegations = len(rows)
    result.audit_events += len(rows)


def _seed_real_mandate_spends(
    tenant_id: str,
    agents_map: dict[str, Agent],
    result: SeedResult,
) -> None:
    """Issue real intent + cart mandate JWTs and record verified spends.

    Every MandateSpend row is backed by a real VC-JWT, so any auditor
    can trace the ledger entry back to a cryptographically verified credential.
    """
    # Mandate scenarios: (agent_name, merchant_name, intent_max, carts)
    # carts: list of (cart_amount_cents, currency)
    scenarios = [
        ("acme-procurement-alpha", "nike-merchant",       50000, [(8999, "USD"), (12500, "USD")]),
        ("acme-procurement-alpha", "office-depot-merchant", 20000, [(4500, "USD"), (3250, "USD"), (5000, "USD")]),
        ("acme-procurement-alpha", "aws-cloud-merchant",  500000, [(250000, "USD"), (170000, "USD")]),
        ("acme-procurement-beta",  "grocery-mart-merchant", 15000, [(8500, "USD")]),
        ("acme-procurement-beta",  "saas-vendor-merchant", 10000, [(5000, "USD")]),
        ("globalbank-trading-bot", "aws-cloud-merchant",  800000, [(300000, "USD"), (400000, "USD")]),
    ]

    intents_seen: set[str] = set()
    spends_count = 0

    for agent_name, merchant_name, intent_max_cents, carts in scenarios:
        if agent_name not in agents_map or merchant_name not in agents_map:
            continue

        agent = agents_map[agent_name]
        merchant = agents_map[merchant_name]

        # Issue real intent mandate JWT
        try:
            intent_cred, intent_jwt = _issue_credential(
                tenant_id,
                agent,  # agent self-issues the intent (in real flow it would be user)
                agent.did,
                "AP2IntentMandate",
                {
                    "mandateType": "AP2IntentMandate",
                    "max_amount": intent_max_cents,
                    "currency": "USD",
                    "merchants": [merchant.did],
                },
                ttl_seconds=86400 * 30,
            )
        except Exception as exc:
            logger.warning("Failed to issue intent mandate for %s: %s", agent_name, exc)
            continue

        intents_seen.add(intent_cred.jti)
        write_audit(
            tenant_id=tenant_id,
            event_type="commerce.mandate.intent.created",
            actor=str(agent.id),
            resource_type="mandate",
            resource_id=intent_cred.jti,
            payload={"mandate_type": "AP2IntentMandate", "agent_did": agent.did,
                     "max_amount": intent_max_cents},
        )
        result.audit_events += 1

        # Issue real cart mandate JWTs and record spends
        cumulative = 0
        for cart_amount, currency in carts:
            if cumulative + cart_amount > intent_max_cents:
                break  # Budget exhausted — don't issue this cart

            try:
                cart_cred, cart_jwt = _issue_credential(
                    tenant_id,
                    agent,
                    agent.did,
                    "AP2CartMandate",
                    {
                        "mandateType": "AP2CartMandate",
                        "parentIntentMandate": intent_jwt,
                        "total": {"value": cart_amount, "currency": currency},
                        "merchant_did": merchant.did,
                    },
                    ttl_seconds=300,
                )
            except Exception as exc:
                logger.warning("Failed to issue cart mandate: %s", exc)
                continue

            write_audit(
                tenant_id=tenant_id,
                event_type="commerce.mandate.cart.created",
                actor=str(agent.id),
                resource_type="mandate",
                resource_id=cart_cred.jti,
                payload={"mandate_type": "AP2CartMandate", "agent_did": agent.did,
                         "cart_value": cart_amount},
            )
            result.audit_events += 1

            # Record the spend with the real cart JTI
            try:
                with db_session() as db:
                    db.add(MandateSpend(
                        id=str(uuid.uuid4()),
                        tenant_id=tenant_id,
                        intent_jti=intent_cred.jti,
                        cart_jti=cart_cred.jti,
                        amount=Decimal(str(cart_amount)),
                        currency=currency,
                        merchant_did=merchant.did,
                        created_at=datetime.now(timezone.utc),
                    ))
                    db.commit()
                cumulative += cart_amount
                spends_count += 1
            except Exception as exc:
                logger.warning("Failed to record spend: %s", exc)

    result.mandate_intents = len(intents_seen)
    result.mandate_spends = spends_count

    write_audit(
        tenant_id=tenant_id,
        event_type="commerce.seed.spends_loaded",
        actor="seed",
        resource_type="mandate_spend",
        resource_id="batch",
        payload={"intents": len(intents_seen), "spends": spends_count},
    )
    result.audit_events += 1


def _gaussian_delta(mean: float, sigma: float) -> int:
    """Return a Gaussian-distributed integer delta."""
    return int(_RNG.gauss(mean, sigma))


def _seed_trust_events(
    tenant_id: str,
    agents_map: dict[str, Agent],
    result: SeedResult,
) -> None:
    """Seed realistic trust event histories with Gaussian-distributed score deltas.

    Each agent has a trajectory (rising/stable/declining/crashed) that shapes
    its event history. Deltas are Gaussian-distributed around trajectory-specific
    means, not hard-coded values.
    """
    trajectory_params = {
        # (mean_delta, sigma, events_count)
        "rising":    (+5.0, 2.5, 12),
        "stable":    (+1.5, 3.5, 10),
        "declining": (-3.0, 4.0, 10),
        "crashed":   (-8.0, 5.0, 8),
    }

    event_type_weights = {
        "rising":   [("verification_success", 0.7), ("delegation_issued", 0.2), ("mandate_verified", 0.1)],
        "stable":   [("verification_success", 0.6), ("verification_failure", 0.3), ("delegation_issued", 0.1)],
        "declining": [("verification_failure", 0.5), ("scope_violation_attempt", 0.3), ("verification_success", 0.2)],
        "crashed":  [("verification_failure", 0.4), ("scope_violation_attempt", 0.4), ("credential_revoked", 0.2)],
    }

    count = 0
    base_time = datetime.now(timezone.utc) - timedelta(days=30)

    with db_session() as db:
        for agent_name, base_score, trajectory, volatility in TRUST_AGENT_PROFILES:
            if agent_name not in agents_map:
                continue
            agent_did = agents_map[agent_name].did
            mean_delta, sigma, n_events = trajectory_params[trajectory]
            # Adjust sigma by agent-specific volatility
            effective_sigma = (sigma + volatility) / 2

            et_weights = event_type_weights[trajectory]
            event_types = [et for et, _ in et_weights]
            et_probs = [p for _, p in et_weights]

            for i in range(n_events):
                delta = max(-25, min(25, _gaussian_delta(mean_delta, effective_sigma)))
                event_type_name = _RNG.choices(event_types, weights=et_probs)[0]
                # Spread events over the past 30 days with some temporal decay
                days_ago = _RNG.uniform(0.1, 30.0)
                event_time = base_time + timedelta(days=30.0 - days_ago)

                event = TrustEvent(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    agent_did=agent_did,
                    event_type=f"trust.{event_type_name}",
                    credential_jti=None,
                    score_delta=delta,
                    metadata_json={"trajectory": trajectory, "volatility": volatility,
                                   "base_score": base_score},
                    created_at=event_time,
                )
                db.add(event)
                count += 1

        db.commit()

    result.trust_events = count


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def seed_tenant(tenant_id: str, profile: str = "standard") -> SeedResult:
    """Populate tenant with a realistic seed ecosystem.

    Idempotent: returns an empty SeedResult if the tenant already has agents.
    All mandate spends are backed by real VC-JWTs for full provenance.
    Trust events use Gaussian-distributed deltas with per-agent trajectories.
    SPIFFE-attested agents have spiffe_id set for bridge-mode resolution.
    """
    with db_session() as db:
        ensure_tenant(db, tenant_id)
        existing = db.execute(
            select(func.count()).select_from(Agent).where(Agent.tenant_id == tenant_id)
        ).scalar()
        if existing and existing > 0:
            logger.info("Tenant %s already has %d agents — skipping seed", tenant_id, existing)
            return SeedResult()

    result = SeedResult()
    agents_map: dict[str, Agent] = {}

    # 1. Create agents (with SPIFFE IDs for attested ones)
    roster = STANDARD_AGENTS if profile == "standard" else MINIMAL_AGENTS
    for name, role, org, spiffe_id in roster:
        try:
            agent, _ = _create_agent(tenant_id, name, spiffe_id=spiffe_id)
        except Exception as exc:
            logger.warning("Failed to create agent %s: %s", name, exc)
            continue
        agents_map[name] = agent
        write_audit(
            tenant_id=tenant_id,
            event_type="agent.created",
            actor="seed",
            resource_type="agent",
            resource_id=str(agent.id),
            payload={"name": name, "role": role, "org": org, "spiffe_id": spiffe_id},
        )
        result.agents += 1
        result.audit_events += 1

    logger.info("Seeded %d agents for tenant %s", result.agents, tenant_id)

    # 2. Issue credentials from the explicit plan
    creds_map: dict[str, Credential] = {}
    plan = CREDENTIAL_PLAN if profile == "standard" else CREDENTIAL_PLAN[:8]

    for issuer_name, subject_name, cred_type, claims in plan:
        if issuer_name not in agents_map or subject_name not in agents_map:
            logger.warning("Skipping credential: missing agent %s or %s", issuer_name, subject_name)
            continue
        issuer = agents_map[issuer_name]
        subject = agents_map[subject_name]
        resolved_claims = _resolve_did_placeholders(claims, agents_map, issuer_name)

        try:
            cred, _ = _issue_credential(tenant_id, issuer, subject.did, cred_type, resolved_claims)
        except Exception as exc:
            logger.warning("Failed to issue %s for %s: %s", cred_type, subject_name, exc)
            continue

        creds_map[subject_name] = cred
        write_audit(
            tenant_id=tenant_id,
            event_type="credential.issued",
            actor=str(issuer.id),
            resource_type="credential",
            resource_id=str(cred.id),
            payload={"jti": cred.jti, "type": cred_type, "subject": subject.did},
        )
        result.credentials += 1
        result.audit_events += 1

    # 3. Bulk AgentCredentials
    if profile == "standard":
        covered_subjects = {row[1] for row in CREDENTIAL_PLAN}
        for subject_name, issuer_name in BULK_AGENT_CRED_SUBJECTS:
            if subject_name in covered_subjects:
                continue
            if issuer_name not in agents_map or subject_name not in agents_map:
                continue
            issuer = agents_map[issuer_name]
            subject = agents_map[subject_name]
            try:
                cred, _ = _issue_credential(
                    tenant_id, issuer, subject.did, "AgentCredential",
                    {"role": subject_name, "seeded": True},
                )
            except Exception as exc:
                logger.warning("Bulk cred failed for %s: %s", subject_name, exc)
                continue

            creds_map.setdefault(subject_name, cred)
            write_audit(
                tenant_id=tenant_id,
                event_type="credential.issued",
                actor=str(issuer.id),
                resource_type="credential",
                resource_id=str(cred.id),
                payload={"jti": cred.jti, "type": "AgentCredential", "subject": subject.did},
            )
            result.credentials += 1
            result.audit_events += 1

    logger.info("Seeded %d credentials for tenant %s", result.credentials, tenant_id)

    # 4. Revoke credentials for decommissioned/rogue agents
    revoke_targets = ["decommissioned-agent", "rogue-test-agent", "temp-contractor-bot"]
    for name in revoke_targets:
        cred = creds_map.get(name)
        if not cred:
            continue
        try:
            set_revoked(cred.status_list_id, cred.status_list_index)
        except Exception as exc:
            logger.warning("Failed to revoke cred for %s: %s", name, exc)
            continue
        write_audit(
            tenant_id=tenant_id,
            event_type="credential.revoked",
            actor="seed",
            resource_type="credential",
            resource_id=str(cred.id),
            payload={"jti": cred.jti, "reason": "decommissioned"},
        )
        result.credentials_revoked += 1
        result.audit_events += 1

    # 5. Register delegation tree
    if profile == "standard" and all(
        n in agents_map for n in ["acme-corp-root-ca", "acme-corp-hr", "acme-procurement-alpha",
                                   "acme-procurement-beta", "acme-procurement-sub"]
    ):
        try:
            _seed_delegation_registry(tenant_id, agents_map, result)
        except Exception as exc:
            logger.warning("Delegation registry seed failed: %s", exc)

    # 6. Real mandate spends (backed by actual VC-JWTs)
    try:
        _seed_real_mandate_spends(tenant_id, agents_map, result)
    except Exception as exc:
        logger.warning("Mandate spend seed failed: %s", exc)

    # 7. Trust events (Gaussian-distributed, trajectory-based)
    try:
        _seed_trust_events(tenant_id, agents_map, result)
    except Exception as exc:
        logger.warning("Trust event seed failed: %s", exc)

    logger.info(
        "Seed complete for tenant %s: %d agents (%d SPIFFE-attested), %d creds, %d revoked, "
        "%d delegations, %d spends, %d trust events, %d audit events",
        tenant_id,
        result.agents,
        sum(1 for a in STANDARD_AGENTS if a[3] is not None),
        result.credentials,
        result.credentials_revoked,
        result.delegations,
        result.mandate_spends,
        result.trust_events,
        result.audit_events,
    )
    return result
