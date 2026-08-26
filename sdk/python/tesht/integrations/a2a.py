"""
tesht.integrations.a2a
~~~~~~~~~~~~~~~~~~~~~~~~
Google A2A (Agent-to-Agent) protocol integration.

Extends A2A Agent Cards with Tesht verifiable identity and provides
helpers for card verification and task-level authentication tokens.
"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

import jwt as pyjwt

from tesht.identity import AgentIdentity, resolve_did_key


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AgentCardVerification:
    """Result of verifying the Tesht identity embedded in an A2A Agent Card."""

    verified: bool
    did: str
    reason: Optional[str]


# ---------------------------------------------------------------------------
# extend_agent_card
# ---------------------------------------------------------------------------

def extend_agent_card(
    card: dict[str, Any],
    identity: AgentIdentity,
    credential_types: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Return a deep copy of *card* enriched with Tesht identity metadata.

    Adds a ``"tesht"`` section and a ``"tesht-vp"`` security scheme
    without mutating the original dict.
    """
    extended = copy.deepcopy(card)

    verification_endpoint: Optional[str] = None
    if identity.method == "web" and identity._domain:
        verification_endpoint = f"https://{identity._domain}/.well-known/did.json"

    extended["tesht"] = {
        "did": identity.did,
        "kid": identity.kid,
        "verificationEndpoint": verification_endpoint,
        "credentialTypes": credential_types if credential_types is not None else ["AgentCredential"],
        "trustScore": None,
    }

    schemes = extended.setdefault("securitySchemes", {})
    schemes["tesht-vp"] = {
        "type": "http",
        "scheme": "bearer",
        "description": "Tesht Verifiable Presentation JWT",
    }

    return extended


# ---------------------------------------------------------------------------
# verify_agent_card_identity
# ---------------------------------------------------------------------------

def verify_agent_card_identity(
    card: dict[str, Any],
    resolver: Optional[Callable[[str], dict[str, Any]]] = None,
) -> AgentCardVerification:
    """
    Verify the Tesht identity advertised in an A2A Agent Card.

    For ``did:key`` DIDs the verification is fully offline.  For other
    methods a *resolver* callback must be supplied.
    """
    tesht_section = card.get("tesht")
    if not tesht_section or not isinstance(tesht_section, dict):
        return AgentCardVerification(verified=False, did="", reason="No tesht section")

    did = tesht_section.get("did", "")
    if not did or not did.startswith("did:"):
        return AgentCardVerification(verified=False, did=did, reason=f"Invalid DID: '{did}'")

    try:
        if did.startswith("did:key:"):
            did_doc = resolve_did_key(did)
        elif resolver is not None:
            did_doc = resolver(did)
        else:
            return AgentCardVerification(
                verified=False,
                did=did,
                reason=f"No resolver for DID method in '{did}'",
            )
    except (ValueError, TypeError) as exc:
        return AgentCardVerification(verified=False, did=did, reason=f"DID resolution failed: {exc}")

    vms = did_doc.get("verificationMethod") or []
    if not vms:
        return AgentCardVerification(verified=False, did=did, reason="No verification methods in DID document")

    for vm in vms:
        if not vm.get("type"):
            return AgentCardVerification(verified=False, did=did, reason="Verification method missing 'type'")
        has_key = "publicKeyMultibase" in vm or "publicKeyJwk" in vm
        if not has_key:
            return AgentCardVerification(
                verified=False,
                did=did,
                reason="Verification method missing key material",
            )

    return AgentCardVerification(verified=True, did=did, reason=None)


# ---------------------------------------------------------------------------
# create_a2a_task_token
# ---------------------------------------------------------------------------

def create_a2a_task_token(
    identity: AgentIdentity,
    target_agent_did: str,
    task_id: str,
) -> str:
    """
    Create a short-lived JWT (5 min) for authenticating a specific A2A task.

    The token binds the caller's DID to a particular task on the target agent.
    """
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": identity.did,
        "aud": target_agent_did,
        "iat": now,
        "exp": now + 300,
        "task_id": task_id,
        "purpose": "a2a_task",
    }
    return pyjwt.encode(
        payload,
        key=identity.private_key,
        algorithm="EdDSA",
        headers={"kid": identity.kid, "typ": "JWT"},
    )
