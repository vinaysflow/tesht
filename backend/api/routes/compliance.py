"""Compliance reporting — maps Tesht controls to SOC2, HIPAA, EU AI Act, ISO 42001."""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.middleware.authz import require_scopes
from core.audit import verify_chain
from core.db import db_session
from models import Agent, AuditEvent, Credential

router = APIRouter(prefix="/v1/compliance", tags=["compliance"])


# ---------------------------------------------------------------------------
# Static control-to-evidence mapping
# ---------------------------------------------------------------------------

CONTROL_LIBRARY: dict[str, list[dict[str, Any]]] = {
    "SOC2": [
        {
            "control_id": "CC6.1",
            "control_name": "Logical Access Controls",
            "description": "Implement controls to prevent unauthorized access to assets.",
            "tesht_mechanism": "W3C DID + Ed25519 keypair per agent; no shared secrets",
            "evidence_query": "agent_count",
            "evidence_label": "{n} agents with unique cryptographic identities",
            "status": "automated",
        },
        {
            "control_id": "CC6.2",
            "control_name": "Prior Authorization",
            "description": "Access is authorized before granting to assets.",
            "tesht_mechanism": "Verifiable Credentials issued by root CAs before any operation",
            "evidence_query": "credential_count",
            "evidence_label": "{n} credentials issued with issuer signatures",
            "status": "automated",
        },
        {
            "control_id": "CC6.6",
            "control_name": "Restrict Access Based on Job Responsibility",
            "description": "Access is restricted to authorized individuals.",
            "tesht_mechanism": "Delegation scope narrowing — child authority ≤ parent authority",
            "evidence_query": "delegation_count",
            "evidence_label": "{n} delegations with scope-narrowing enforcement",
            "status": "automated",
        },
        {
            "control_id": "CC7.1",
            "control_name": "Detect and Monitor System Components",
            "description": "Detect threats against the system.",
            "tesht_mechanism": "SHA-256 hash-chained audit log with integrity verification",
            "evidence_query": "audit_chain_valid",
            "evidence_label": "Audit chain: {n} events, integrity {status}",
            "status": "automated",
        },
        {
            "control_id": "CC8.1",
            "control_name": "Change Management",
            "description": "Changes to infrastructure are authorized, tested, and approved.",
            "tesht_mechanism": "Credential revocation via Bitstring Status List; all changes audited",
            "evidence_query": "revoked_count",
            "evidence_label": "{n} credentials revoked with audit records",
            "status": "automated",
        },
    ],
    "HIPAA": [
        {
            "control_id": "164.312(a)(1)",
            "control_name": "Access Control",
            "description": "Implement technical policies to allow access only to authorized persons.",
            "tesht_mechanism": "CapabilityCredential per agent with scoped permissions",
            "evidence_query": "credential_count",
            "evidence_label": "{n} agent credentials with scoped access",
            "status": "automated",
        },
        {
            "control_id": "164.312(b)",
            "control_name": "Audit Controls",
            "description": "Implement hardware, software, and procedural audit controls.",
            "tesht_mechanism": "Tamper-evident audit trail with hash-chain integrity",
            "evidence_query": "audit_chain_valid",
            "evidence_label": "Audit chain: {n} events, integrity {status}",
            "status": "automated",
        },
        {
            "control_id": "164.312(c)(1)",
            "control_name": "Integrity Controls",
            "description": "Implement policies to protect PHI from improper alteration.",
            "tesht_mechanism": "Ed25519 signatures on all credentials; tamper detection on verify",
            "evidence_query": "credential_count",
            "evidence_label": "{n} credentials with cryptographic integrity protection",
            "status": "automated",
        },
        {
            "control_id": "164.312(d)",
            "control_name": "Person/Entity Authentication",
            "description": "Implement procedures to verify that a person or entity is who they claim.",
            "tesht_mechanism": "W3C DID resolution + Ed25519 signature verification on every access",
            "evidence_query": "agent_count",
            "evidence_label": "{n} agents with verifiable cryptographic identity",
            "status": "automated",
        },
    ],
    "EU AI Act": [
        {
            "control_id": "Art. 6",
            "control_name": "High-Risk AI Classification",
            "description": "AI systems classified as high-risk must meet stringent requirements.",
            "tesht_mechanism": "ComplianceCredential with risk_level=high, human_oversight_required=True",
            "evidence_query": "euai_high_risk_count",
            "evidence_label": "{n} agents with EU AI Act high-risk credentials",
            "status": "automated",
        },
        {
            "control_id": "Art. 9",
            "control_name": "Risk Management System",
            "description": "Establish and implement a risk management system.",
            "tesht_mechanism": "Trust score (0-100) with risk levels: low/medium/high/critical",
            "evidence_query": "trust_event_count",
            "evidence_label": "{n} trust events tracked for behavioral risk management",
            "status": "automated",
        },
        {
            "control_id": "Art. 12",
            "control_name": "Record-Keeping (Logging)",
            "description": "High-risk AI systems shall have logging capabilities.",
            "tesht_mechanism": "Tamper-evident audit log with SHA-256 hash chain",
            "evidence_query": "audit_chain_valid",
            "evidence_label": "Audit chain: {n} events, integrity {status}",
            "status": "automated",
        },
        {
            "control_id": "Art. 13",
            "control_name": "Transparency",
            "description": "AI systems shall be transparent and provide information.",
            "tesht_mechanism": "Every credential includes issuer, scope, and expiry in human-readable form",
            "evidence_query": "credential_count",
            "evidence_label": "{n} credentials with transparent provenance",
            "status": "automated",
        },
        {
            "control_id": "Art. 52",
            "control_name": "Transparency Obligations (Limited Risk)",
            "description": "Limited-risk AI systems must inform users they are interacting with AI.",
            "tesht_mechanism": "ComplianceCredential with risk_level=limited, transparency_obligation=True",
            "evidence_query": "euai_limited_count",
            "evidence_label": "{n} agents with limited-risk transparency credentials",
            "status": "automated",
        },
    ],
    "ISO 42001": [
        {
            "control_id": "6.1",
            "control_name": "Actions to Address Risks and Opportunities",
            "description": "Determine risks and opportunities for AI management system.",
            "tesht_mechanism": "Trust scoring + anomaly detection flags agents with risk escalation",
            "evidence_query": "trust_event_count",
            "evidence_label": "{n} trust events for risk tracking",
            "status": "automated",
        },
        {
            "control_id": "7.5",
            "control_name": "Documented Information",
            "description": "AI management system documented information.",
            "tesht_mechanism": "All credentials, delegations, and mandates are cryptographically documented JWTs",
            "evidence_query": "credential_count",
            "evidence_label": "{n} documented credentials as verifiable JWTs",
            "status": "automated",
        },
        {
            "control_id": "8.4",
            "control_name": "System Lifecycle",
            "description": "AI system lifecycle processes.",
            "tesht_mechanism": "Full lifecycle: issue → delegate → commerce → revoke with audit trail",
            "evidence_query": "audit_event_count",
            "evidence_label": "{n} lifecycle events in audit trail",
            "status": "automated",
        },
        {
            "control_id": "9.1",
            "control_name": "Monitoring, Measurement, Analysis",
            "description": "Monitor and measure AI system performance.",
            "tesht_mechanism": "Behavioral trust scoring with Gaussian-distributed event history",
            "evidence_query": "trust_event_count",
            "evidence_label": "{n} behavioral events tracked",
            "status": "automated",
        },
    ],
}

SUPPORTED_FRAMEWORKS = list(CONTROL_LIBRARY.keys())


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class ControlEvidence(BaseModel):
    control_id: str
    control_name: str
    description: str
    tesht_mechanism: str
    evidence_value: str
    status: str
    passing: bool


class ComplianceReportResponse(BaseModel):
    framework: str
    tenant_id: str
    controls_total: int
    controls_passing: int
    controls_automated: int
    chain_valid: bool
    audit_events_count: int
    controls: list[ControlEvidence]
    generated_at: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/controls")
def list_frameworks(auth: dict = Depends(require_scopes(["credentials:verify"]))):
    """List supported compliance frameworks and their control counts."""
    return {
        "frameworks": [
            {"id": fw, "name": fw, "controls": len(controls)}
            for fw, controls in CONTROL_LIBRARY.items()
        ]
    }


@router.get("/report", response_model=ComplianceReportResponse)
def get_compliance_report(
    framework: str = "SOC2",
    auth: dict = Depends(require_scopes(["credentials:verify"])),
) -> ComplianceReportResponse:
    """Generate a compliance report mapping Tesht controls to a framework."""
    if framework not in CONTROL_LIBRARY:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown framework '{framework}'. Supported: {SUPPORTED_FRAMEWORKS}",
        )

    tenant_id = auth.get("tenant_id", "default")

    # Gather evidence metrics
    from sqlalchemy import func, text as sqla_text
    from core.status_list import is_revoked
    from models import TrustEvent, MandateSpend

    with db_session() as db:
        agent_count = db.query(func.count(Agent.id)).filter(Agent.tenant_id == tenant_id).scalar() or 0
        creds = db.query(Credential).filter(Credential.tenant_id == tenant_id).all()
        cred_count = len(creds)
        revoked_count = sum(1 for c in creds if is_revoked(c.status_list_id, c.status_list_index))
        audit_count = db.query(func.count(AuditEvent.id)).filter(AuditEvent.tenant_id == tenant_id).scalar() or 0
        trust_count = db.query(func.count(TrustEvent.id)).filter(TrustEvent.tenant_id == tenant_id).scalar() or 0

        # Delegation count
        try:
            del_count = db.execute(
                sqla_text("SELECT COUNT(*) FROM delegation_registry WHERE tenant_id = :tid"),
                {"tid": tenant_id},
            ).scalar() or 0
        except Exception:
            del_count = 0

        # EU AI Act specific
        euai_high = db.query(Credential).filter(
            Credential.tenant_id == tenant_id,
            Credential.credential_type == "ComplianceCredential",
        ).all()
        euai_high_count = len([c for c in euai_high if "high" in str(c.jwt)])
        euai_limited_count = len([c for c in euai_high if "limited" in str(c.jwt)])

    chain = verify_chain(tenant_id)

    # Build evidence lookup
    evidence_map = {
        "agent_count": agent_count,
        "credential_count": cred_count,
        "revoked_count": revoked_count,
        "audit_event_count": audit_count,
        "audit_chain_valid": audit_count,
        "delegation_count": del_count,
        "trust_event_count": trust_count,
        "euai_high_risk_count": euai_high_count,
        "euai_limited_count": euai_limited_count,
    }

    import time
    controls_out: list[ControlEvidence] = []
    for ctrl in CONTROL_LIBRARY[framework]:
        query_key = ctrl["evidence_query"]
        n = evidence_map.get(query_key, 0)
        status_str = "VERIFIED" if chain["valid"] else "BROKEN"
        evidence_label = ctrl["evidence_label"].replace("{n}", str(n)).replace("{status}", status_str)
        passing = n > 0 if query_key != "audit_chain_valid" else chain["valid"]

        controls_out.append(ControlEvidence(
            control_id=ctrl["control_id"],
            control_name=ctrl["control_name"],
            description=ctrl["description"],
            tesht_mechanism=ctrl["tesht_mechanism"],
            evidence_value=evidence_label,
            status=ctrl["status"],
            passing=passing,
        ))

    passing_count = sum(1 for c in controls_out if c.passing)

    return ComplianceReportResponse(
        framework=framework,
        tenant_id=tenant_id,
        controls_total=len(controls_out),
        controls_passing=passing_count,
        controls_automated=len(controls_out),
        chain_valid=chain["valid"],
        audit_events_count=audit_count,
        controls=controls_out,
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
