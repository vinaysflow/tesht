from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

import jwt as pyjwt

from core.db import db_session
from core.resolver import resolve_did
from core.status_list_vc import (
    is_local_status_list_url,
    issue_status_list_vc_jwt,
    status_list_id_from_url,
    verify_and_extract_encoded_list,
)
from core.vc import verify_vc_jwt
from models import Agent, Credential, StatusList, TrustEvent

import httpx


@dataclass
class TrustScore:
    """Composite 0-100 trust rating for a Verifiable Credential."""
    total: int
    factors: dict[str, int]
    risk_level: str
    explanation: str
    computed_at: str


def _status_check(status_list_cred_url: str, index: int) -> bool:
    if is_local_status_list_url(status_list_cred_url):
        sl_id = status_list_id_from_url(status_list_cred_url)
        status_jwt, _ = issue_status_list_vc_jwt(sl_id)
    else:
        r = httpx.get(status_list_cred_url, timeout=10.0)
        r.raise_for_status()
        data = r.json()
        status_jwt = data.get("jwt")
        if not isinstance(status_jwt, str):
            raise ValueError("status list response missing jwt")
    raw_bits, _ = verify_and_extract_encoded_list(status_jwt)
    if index < 0 or index >= (len(raw_bits) * 8):
        return False
    byte_i = index // 8
    bit_i = index % 8
    return (raw_bits[byte_i] & (1 << bit_i)) != 0


def _factor_credential_validity(token: str) -> tuple[int, str]:
    """
    Factor 1: Credential Validity (0-25).

    Returns (score, explanation).
    """
    # First decode without verification to get exp and check for expiry state.
    try:
        unverified = pyjwt.decode(token, options={"verify_signature": False})
    except Exception:
        return 0, "Invalid JWT — cannot decode"

    exp = unverified.get("exp")
    now = int(time.time())

    # Try full signature + status verification.
    try:
        result = verify_vc_jwt(token=token, resolve_did_document=resolve_did, status_check=_status_check)
    except pyjwt.ExpiredSignatureError:
        if exp is not None:
            seconds_past = now - exp
            if 0 < seconds_past < 3600:
                return 10, "VC expired but within 1-hour grace period"
            return 5, f"VC expired {seconds_past}s ago"
        return 5, "VC expired"
    except Exception as exc:
        return 0, f"VC signature invalid: {exc}"

    if result["status"].get("present") and result["status"].get("revoked"):
        return 0, "VC is revoked"

    if not result["status"].get("present"):
        # No status list entry — revocation unknown
        return 20, "VC valid; revocation status unknown (no status checker)"

    return 25, "VC valid, not expired, not revoked"


def _factor_issuer_reputation(issuer_did: str, tenant_id: str) -> tuple[int, str]:
    """
    Factor 2: Issuer Reputation (0-25).

    Queries the credentials table via the issuer DID to compute revocation_rate.
    """
    with db_session() as db:
        issuer_agent = db.query(Agent).filter(Agent.did == issuer_did).first()
        if issuer_agent is None:
            return 10, "Issuer unknown — neutral score"

        credentials = (
            db.query(Credential)
            .filter(
                Credential.issuer_agent_id == issuer_agent.id,
                Credential.tenant_id == tenant_id,
            )
            .all()
        )
        total_issued = len(credentials)
        if total_issued == 0:
            return 10, "Issuer has issued no credentials — neutral score"

        total_revoked = 0
        for cred in credentials:
            try:
                sl = db.query(StatusList).filter(StatusList.id == cred.status_list_id).first()
                if sl is not None:
                    import base64 as _base64

                    def _b64url_decode(s: str) -> bytes:
                        padded = s + "=" * ((4 - len(s) % 4) % 4)
                        return _base64.urlsafe_b64decode(padded.encode("ascii"))

                    raw_bits = _b64url_decode(sl.bitstring)
                    idx = cred.status_list_index
                    if 0 <= idx < len(raw_bits) * 8:
                        byte_i = idx // 8
                        bit_i = idx % 8
                        if (raw_bits[byte_i] & (1 << bit_i)) != 0:
                            total_revoked += 1
            except Exception:
                pass

    revocation_rate = total_revoked / max(total_issued, 1)

    if revocation_rate < 0.05:
        return 25, f"Excellent issuer: {total_issued} issued, {total_revoked} revoked ({revocation_rate:.1%} rate)"
    if revocation_rate < 0.10:
        return 20, f"Good issuer: {revocation_rate:.1%} revocation rate"
    if revocation_rate < 0.20:
        return 15, f"Fair issuer: {revocation_rate:.1%} revocation rate"
    if revocation_rate < 0.50:
        return 10, f"Poor issuer: {revocation_rate:.1%} revocation rate"
    return 5, f"Dangerous issuer: {revocation_rate:.1%} revocation rate"


def _factor_agent_history(agent_did: str, tenant_id: str) -> tuple[int, str]:
    """
    Factor 3: Agent History (0-25).

    Counts verification_success / verification_failure events for the agent.
    """
    with db_session() as db:
        events = (
            db.query(TrustEvent)
            .filter(
                TrustEvent.agent_did == agent_did,
                TrustEvent.tenant_id == tenant_id,
                TrustEvent.event_type.in_(["verification_success", "verification_failure"]),
            )
            .all()
        )

    successful = sum(1 for e in events if e.event_type == "verification_success")
    failed = sum(1 for e in events if e.event_type == "verification_failure")
    total = successful + failed

    if total == 0:
        return 10, "New agent — neutral score"

    success_rate = successful / max(total, 1)

    if total >= 10 and success_rate >= 0.95:
        return 25, f"Excellent history: {successful}/{total} successful ({success_rate:.1%})"
    if total >= 5 and success_rate >= 0.90:
        return 20, f"Good history: {successful}/{total} successful ({success_rate:.1%})"
    if success_rate >= 0.80:
        return 15, f"Fair history: {success_rate:.1%} success rate"
    if success_rate >= 0.50:
        return 10, f"Mixed history: {success_rate:.1%} success rate"
    return 5, f"Poor history: {success_rate:.1%} success rate"


def _factor_delegation_depth(payload: dict[str, Any]) -> tuple[int, str]:
    """
    Factor 4: Delegation Depth (0-25).

    Inspects the JWT payload for delegation depth indicators.
    """
    vc = payload.get("vc") or {}
    cs = vc.get("credentialSubject") or {}

    # Explicit depth field set by sdk/python/tesht/delegation.py
    depth = cs.get("depth")
    if depth is not None:
        try:
            depth = int(depth)
        except (TypeError, ValueError):
            depth = 0
    else:
        # Infer from presence of parent delegation fields
        has_parent = bool(
            cs.get("parentDelegation")
            or cs.get("parentIntentMandate")
            or cs.get("delegationChain")
        )
        depth = 1 if has_parent else 0

    scores = {0: 25, 1: 20, 2: 15, 3: 10, 4: 5}
    score = scores.get(depth, 0)
    return score, f"Delegation depth {depth}"


def _risk_level(total: int) -> str:
    if total >= 75:
        return "low"
    if total >= 50:
        return "medium"
    if total >= 25:
        return "high"
    return "critical"


def compute_trust_score(token: str, tenant_id: str) -> TrustScore:
    """
    Compute a composite 0-100 trust score for a VC-JWT.

    The score is the sum of four factors, each 0-25.
    """
    # Decode to extract issuer/subject DIDs without raising on expiry.
    try:
        payload = pyjwt.decode(token, options={"verify_signature": False})
    except Exception as exc:
        factors = {
            "credential_validity": 0,
            "issuer_reputation": 0,
            "agent_history": 0,
            "delegation_depth": 0,
        }
        return TrustScore(
            total=0,
            factors=factors,
            risk_level="critical",
            explanation=f"Cannot decode JWT: {exc}",
            computed_at=datetime.utcnow().isoformat() + "Z",
        )

    issuer_did = payload.get("iss", "")
    subject_did = payload.get("sub", "")

    f1_score, f1_note = _factor_credential_validity(token)
    f2_score, f2_note = _factor_issuer_reputation(issuer_did, tenant_id)
    f3_score, f3_note = _factor_agent_history(subject_did, tenant_id)
    f4_score, f4_note = _factor_delegation_depth(payload)

    total = f1_score + f2_score + f3_score + f4_score
    factors = {
        "credential_validity": f1_score,
        "issuer_reputation": f2_score,
        "agent_history": f3_score,
        "delegation_depth": f4_score,
    }
    risk = _risk_level(total)

    explanation = (
        f"Score {total}/100 ({risk} risk). "
        f"Validity: {f1_score}/25 ({f1_note}). "
        f"Issuer: {f2_score}/25 ({f2_note}). "
        f"Agent: {f3_score}/25 ({f3_note}). "
        f"Delegation: {f4_score}/25 ({f4_note})."
    )

    return TrustScore(
        total=total,
        factors=factors,
        risk_level=risk,
        explanation=explanation,
        computed_at=datetime.utcnow().isoformat() + "Z",
    )


def record_trust_event(
    *,
    tenant_id: str,
    agent_did: str,
    event_type: str,
    credential_jti: Optional[str] = None,
    score_delta: int = 0,
    metadata: Optional[dict[str, Any]] = None,
) -> TrustEvent:
    """Persist a trust event for an agent DID."""
    event = TrustEvent(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        agent_did=agent_did,
        event_type=event_type,
        credential_jti=credential_jti,
        score_delta=score_delta,
        metadata_json=metadata or {},
        created_at=datetime.utcnow(),
    )
    with db_session() as db:
        db.add(event)
        db.commit()
        db.refresh(event)
    return event


def get_agent_trust_profile(agent_did: str, tenant_id: str) -> dict[str, Any]:
    """
    Return an aggregate trust profile for an agent DID.

    Includes success_rate, average score delta, and last 20 events.
    """
    with db_session() as db:
        all_events = (
            db.query(TrustEvent)
            .filter(
                TrustEvent.agent_did == agent_did,
                TrustEvent.tenant_id == tenant_id,
            )
            .order_by(TrustEvent.created_at.desc())
            .all()
        )

        total_events = len(all_events)
        successful = sum(1 for e in all_events if e.event_type == "verification_success")
        failed = sum(1 for e in all_events if e.event_type == "verification_failure")
        verification_total = successful + failed
        success_rate = (successful / verification_total) if verification_total > 0 else None

        score_deltas = [e.score_delta for e in all_events if e.score_delta != 0]
        average_score = (sum(score_deltas) / len(score_deltas)) if score_deltas else None

        last_scored_at = all_events[0].created_at.isoformat() + "Z" if all_events else None

        history = [
            {
                "event_type": e.event_type,
                "created_at": e.created_at.isoformat() + "Z",
                "score_delta": e.score_delta,
                "credential_jti": e.credential_jti,
            }
            for e in all_events[:20]
        ]

    return {
        "did": agent_did,
        "total_events": total_events,
        "success_rate": success_rate,
        "average_score": average_score,
        "last_scored_at": last_scored_at,
        "history": history,
    }
