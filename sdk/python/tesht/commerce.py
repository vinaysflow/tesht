"""
tesht.commerce
~~~~~~~~~~~~~~~~
AP2-compatible mandate issuance and verification.

AP2 (Agent Payment Protocol) uses two mandate types:

- AP2IntentMandate: issued by a user/delegator to an agent, describing what
  the agent is authorised to purchase (intent-level, before a specific cart).
- AP2CartMandate: issued once a specific cart is confirmed; references the
  parent intent mandate and must stay within its budget.

Both mandate types are standard W3C VC-JWTs, issued via issue_vc() and
verifiable with verify_vc().  The commerce module adds:
- Input validation specific to mandate fields.
- Parent-mandate cross-checking for carts (total <= intent max_amount).
- A structured MandateVerification result type.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional

from tesht.credentials import issue_vc, verify_vc
from tesht.identity import AgentIdentity


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class MandateVerification:
    """Result of verifying an AP2 mandate VC-JWT."""
    verified: bool
    mandate_type: str                  # "AP2IntentMandate" | "AP2CartMandate" | ""
    mandate_id: str                    # jti of the mandate JWT
    delegator_did: str                 # who issued the mandate
    agent_did: str                     # subject — the authorised agent
    scope: dict[str, Any]             # {max_amount, currency, merchants, categories, ...}
    reason: Optional[str]             # None if verified=True, else explanation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_iso8601(value: str) -> None:
    """Raise ValueError if value is not a parseable ISO 8601 datetime string."""
    try:
        # Accept both 'Z' suffix and '+00:00' offset
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ValueError(
            f"intent_expiry must be a valid ISO 8601 datetime string, got '{value}'"
        ) from exc


def _validate_currency(currency: str) -> None:
    if len(currency) != 3 or not currency.isalpha() or not currency.isupper():
        raise ValueError(
            f"currency must be a 3-letter ISO 4217 code, got '{currency}'"
        )


# ---------------------------------------------------------------------------
# issue_intent_mandate
# ---------------------------------------------------------------------------

def issue_intent_mandate(
    delegator: AgentIdentity,
    agent_did: str,
    intent: dict[str, Any],
    ttl_seconds: int = 3600,
) -> str:
    """
    Issue an AP2IntentMandate VC-JWT.

    The mandate authorises `agent_did` to act on the delegator's behalf
    within the constraints described in `intent`.

    Required intent fields:
    - max_amount (int, > 0)  — spending limit in the smallest currency unit (e.g. cents)
    - currency (str)          — 3-letter ISO 4217 code (e.g. "USD")

    Optional intent fields:
    - mandate_id (str)        — stable mandate identifier; generated if omitted
    - description (str)
    - merchants (list[str])   — allowed merchant DIDs or ["*"] for any
    - categories (list[str])
    - requires_refundability (bool)
    - user_cart_confirmation_required (bool)
    - intent_expiry (str)     — ISO 8601 datetime string

    Raises:
        ValueError: if required fields are missing or invalid.
    """
    max_amount = intent.get("max_amount")
    if max_amount is None:
        raise ValueError("intent.max_amount is required")
    if not isinstance(max_amount, int) or max_amount <= 0:
        raise ValueError(f"intent.max_amount must be a positive integer, got {max_amount!r}")

    currency = intent.get("currency")
    if not currency:
        raise ValueError("intent.currency is required")
    _validate_currency(str(currency))

    intent_expiry = intent.get("intent_expiry")
    if intent_expiry is not None:
        _parse_iso8601(str(intent_expiry))

    mandate_id = intent.get("mandate_id") or str(uuid.uuid4())

    claims: dict[str, Any] = {
        "mandateId": mandate_id,
        "mandateType": "AP2IntentMandate",
        "delegatedBy": delegator.did,
        "max_amount": max_amount,
        "currency": currency,
    }
    for optional_field in (
        "description",
        "merchants",
        "categories",
        "requires_refundability",
        "user_cart_confirmation_required",
        "intent_expiry",
    ):
        if optional_field in intent:
            claims[optional_field] = intent[optional_field]

    return issue_vc(
        issuer=delegator,
        subject_did=agent_did,
        credential_type="AP2IntentMandate",
        claims=claims,
        ttl_seconds=ttl_seconds,
        credential_id=mandate_id,
    )


# ---------------------------------------------------------------------------
# issue_cart_mandate
# ---------------------------------------------------------------------------

def issue_cart_mandate(
    delegator: AgentIdentity,
    agent_did: str,
    cart: dict[str, Any],
    intent_mandate_jwt: str,
    ttl_seconds: int = 300,
) -> str:
    """
    Issue an AP2CartMandate VC-JWT, referencing a parent intent mandate.

    The cart total must be <= the intent's max_amount.

    Required cart fields:
    - total (dict)            — {"currency": str, "value": int}  (value in cents)

    Optional cart fields:
    - mandate_id (str)
    - parent_intent_mandate_id (str)
    - items (list[dict])
    - merchant_did (str)
    - shipping_address_hash (str)
    - payment_method_type (str)

    Raises:
        ValueError: if cart total exceeds intent max_amount, or if the
                    parent intent mandate is invalid/expired.
    """
    # Verify parent intent mandate
    intent_result = verify_vc(intent_mandate_jwt)
    if not intent_result.verified:
        raise ValueError(
            f"Parent intent mandate is invalid: {intent_result.reason}"
        )

    intent_claims = intent_result.claims
    intent_max_amount = intent_claims.get("max_amount", 0)
    intent_currency = intent_claims.get("currency", "")

    # Validate cart total
    total = cart.get("total")
    if total is None:
        raise ValueError("cart.total is required")
    cart_value = total.get("value")
    if cart_value is None:
        raise ValueError("cart.total.value is required")
    if not isinstance(cart_value, int) or cart_value < 0:
        raise ValueError(f"cart.total.value must be a non-negative integer, got {cart_value!r}")

    if cart_value > intent_max_amount:
        raise ValueError(
            f"Cart total {cart_value} exceeds intent limit {intent_max_amount}"
        )

    # Currency must match between cart and intent
    cart_total_currency = total.get("currency", "")
    if intent_currency and cart_total_currency and cart_total_currency != intent_currency:
        raise ValueError(
            f"Cart currency '{cart_total_currency}' does not match intent currency '{intent_currency}'"
        )

    mandate_id = cart.get("mandate_id") or str(uuid.uuid4())

    claims: dict[str, Any] = {
        "mandateId": mandate_id,
        "mandateType": "AP2CartMandate",
        "delegatedBy": delegator.did,
        "parentIntentMandate": intent_mandate_jwt,
        "total": total,
    }
    for optional_field in (
        "parent_intent_mandate_id",
        "items",
        "merchant_did",
        "shipping_address_hash",
        "payment_method_type",
    ):
        if optional_field in cart:
            claims[optional_field] = cart[optional_field]

    return issue_vc(
        issuer=delegator,
        subject_did=agent_did,
        credential_type="AP2CartMandate",
        claims=claims,
        ttl_seconds=ttl_seconds,
        credential_id=mandate_id,
    )


# ---------------------------------------------------------------------------
# verify_mandate
# ---------------------------------------------------------------------------

def verify_mandate(
    token: str,
    mandate_type: Optional[str] = None,
    resolver: Optional[Callable[[str], dict[str, Any]]] = None,
    status_checker: Optional[Callable[[str, int], bool]] = None,
) -> MandateVerification:
    """
    Verify an AP2 mandate VC-JWT.

    For AP2CartMandate, also verifies the embedded parent intent mandate and
    checks that the cart total does not exceed the intent's max_amount.

    Args:
        token:         The mandate VC-JWT string.
        mandate_type:  If provided, the actual credential type must match.
                       Use "AP2IntentMandate" or "AP2CartMandate".
        resolver:      DID resolver for non-did:key issuers.
        status_checker: Revocation checker callback.

    Returns:
        MandateVerification with verified=True on success, or verified=False
        with a reason string explaining the failure.
    """
    _empty = MandateVerification(
        verified=False,
        mandate_type="",
        mandate_id="",
        delegator_did="",
        agent_did="",
        scope={},
        reason=None,
    )

    vc_result = verify_vc(token, resolver=resolver, status_checker=status_checker)
    if not vc_result.verified:
        return MandateVerification(
            verified=False,
            mandate_type="",
            mandate_id="",
            delegator_did="",
            agent_did="",
            scope={},
            reason=vc_result.reason,
        )

    actual_type = vc_result.credential_type
    claims = vc_result.claims

    # Mandate type mismatch check
    if mandate_type is not None and actual_type != mandate_type:
        return MandateVerification(
            verified=False,
            mandate_type=actual_type,
            mandate_id=claims.get("mandateId", vc_result.payload.get("jti", "")),
            delegator_did=claims.get("delegatedBy", ""),
            agent_did=vc_result.subject_did,
            scope={},
            reason=f"Mandate type mismatch: expected '{mandate_type}', got '{actual_type}'",
        )

    mandate_id = claims.get("mandateId") or vc_result.payload.get("jti", "")
    delegator_did = claims.get("delegatedBy", vc_result.issuer_did)
    agent_did = vc_result.subject_did

    # Build scope from intent-level fields (present on both types)
    scope: dict[str, Any] = {}
    for field_name in ("max_amount", "currency", "merchants", "categories"):
        if field_name in claims:
            scope[field_name] = claims[field_name]

    # For cart mandates, verify the parent intent and cross-check budget
    if actual_type == "AP2CartMandate":
        parent_jwt = claims.get("parentIntentMandate")
        if not parent_jwt:
            return MandateVerification(
                verified=False,
                mandate_type=actual_type,
                mandate_id=mandate_id,
                delegator_did=delegator_did,
                agent_did=agent_did,
                scope=scope,
                reason="AP2CartMandate is missing parentIntentMandate claim",
            )

        parent_result = verify_vc(parent_jwt, resolver=resolver, status_checker=status_checker)
        if not parent_result.verified:
            return MandateVerification(
                verified=False,
                mandate_type=actual_type,
                mandate_id=mandate_id,
                delegator_did=delegator_did,
                agent_did=agent_did,
                scope=scope,
                reason=f"Parent intent mandate invalid: {parent_result.reason}",
            )

        # Check currency match — cart and intent must use the same currency
        intent_currency = parent_result.claims.get("currency", "")
        intent_max = parent_result.claims.get("max_amount", 0)
        cart_total_dict = claims.get("total", {})
        cart_value = cart_total_dict.get("value", 0) if isinstance(cart_total_dict, dict) else 0
        cart_currency = cart_total_dict.get("currency", "") if isinstance(cart_total_dict, dict) else ""

        if intent_currency and cart_currency and cart_currency != intent_currency:
            return MandateVerification(
                verified=False,
                mandate_type=actual_type,
                mandate_id=mandate_id,
                delegator_did=delegator_did,
                agent_did=agent_did,
                scope=scope,
                reason=f"Currency mismatch: cart uses '{cart_currency}' but intent requires '{intent_currency}'",
            )

        # Check cart total <= intent max_amount

        if cart_value > intent_max:
            return MandateVerification(
                verified=False,
                mandate_type=actual_type,
                mandate_id=mandate_id,
                delegator_did=delegator_did,
                agent_did=agent_did,
                scope=scope,
                reason=f"Cart total {cart_value} exceeds intent limit {intent_max}",
            )

        # Inherit scope from parent intent for the verification result
        for field_name in ("max_amount", "currency", "merchants", "categories"):
            if field_name in parent_result.claims and field_name not in scope:
                scope[field_name] = parent_result.claims[field_name]

    return MandateVerification(
        verified=True,
        mandate_type=actual_type,
        mandate_id=mandate_id,
        delegator_did=delegator_did,
        agent_did=agent_did,
        scope=scope,
        reason=None,
    )
