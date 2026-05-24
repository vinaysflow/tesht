"""
idp_bridge.validator
~~~~~~~~~~~~~~~~~~~~
Multi-issuer OIDC token validator.

Accepts tokens from any IdP registered in the IdPRegistryConfig.
Uses one PyJWKClient per provider, created lazily and cached.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import jwt

from idp_bridge.config import IdPRegistryConfig, TrustedIdP


@dataclass
class OIDCValidationResult:
    """Outcome of validating an OIDC id_token."""

    valid: bool
    provider_id: Optional[str] = None
    provider_name: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    mapped_claims: dict[str, Any] = field(default_factory=dict)
    raw_claims: dict[str, Any] = field(default_factory=dict)
    reason: Optional[str] = None


class MultiIssuerOIDCValidator:
    """Validates OIDC tokens against any trusted IdP in the registry."""

    def __init__(self, registry: IdPRegistryConfig) -> None:
        self.registry = registry
        self._jwks_clients: dict[str, jwt.PyJWKClient] = {}

    def validate_token(self, token: str) -> OIDCValidationResult:
        """Validate an OIDC id_token against the trusted IdP registry.

        Steps:
        1. Decode header + payload without signature to extract ``iss``.
        2. Find matching IdP by issuer URL.
        3. Get (or create) a PyJWKClient for that IdP's JWKS endpoint.
        4. Verify signature, expiry, and optional audience.
        5. Map claims via the IdP's ``claim_mapping``.
        """
        # Step 1: peek at the payload without verifying signature
        try:
            unverified = jwt.decode(
                token, options={"verify_signature": False}
            )
        except Exception as exc:
            return OIDCValidationResult(
                valid=False, reason=f"Malformed token: {exc}"
            )

        issuer = unverified.get("iss")
        if not issuer:
            return OIDCValidationResult(
                valid=False, reason="Token missing 'iss' claim"
            )

        # Step 2: find provider
        match = self.registry.find_by_issuer(issuer)
        if match is None:
            return OIDCValidationResult(
                valid=False,
                issuer=issuer,
                reason=f"Untrusted issuer: {issuer!r} not in IdP registry",
            )
        provider_id, provider = match

        # Step 3: get JWKS client
        try:
            client = self._get_jwks_client(provider_id, provider)
        except Exception as exc:
            return OIDCValidationResult(
                valid=False,
                provider_id=provider_id,
                provider_name=provider.name,
                issuer=issuer,
                reason=f"Failed to fetch JWKS for {provider.name}: {exc}",
            )

        # Step 4: verify signature + standard claims
        try:
            signing_key = client.get_signing_key_from_jwt(token).key
        except Exception as exc:
            return OIDCValidationResult(
                valid=False,
                provider_id=provider_id,
                provider_name=provider.name,
                issuer=issuer,
                reason=f"JWKS key lookup failed: {exc}",
            )

        # Accept both trailing-slash and no-trailing-slash forms of the issuer.
        # Auth0 puts a trailing slash in tokens; config often omits it.
        issuer_claim = unverified.get("iss", "")
        configured_issuer = provider.issuer
        # Use whichever form the token actually carries, as long as they
        # normalize to the same value — the find_by_issuer() already confirmed
        # they match, so we just tell PyJWT to accept the token's own iss value.
        effective_issuer = issuer_claim if issuer_claim.rstrip("/") == configured_issuer.rstrip("/") else configured_issuer

        decode_opts: dict[str, Any] = {
            "algorithms": provider.allowed_algorithms,
            "issuer": effective_issuer,
            "options": {"require": ["iss", "sub", "iat", "exp"]},
        }
        if provider.audience:
            decode_opts["audience"] = provider.audience
        else:
            decode_opts["options"]["verify_aud"] = False

        try:
            claims = jwt.decode(token, signing_key, **decode_opts)
        except jwt.ExpiredSignatureError:
            return OIDCValidationResult(
                valid=False,
                provider_id=provider_id,
                provider_name=provider.name,
                issuer=issuer,
                reason="Token has expired",
            )
        except Exception as exc:
            return OIDCValidationResult(
                valid=False,
                provider_id=provider_id,
                provider_name=provider.name,
                issuer=issuer,
                reason=f"Token verification failed: {exc}",
            )

        # Step 5: map claims
        mapped = _map_claims(claims, provider.claim_mapping)

        return OIDCValidationResult(
            valid=True,
            provider_id=provider_id,
            provider_name=provider.name,
            issuer=issuer,
            subject=claims.get("sub"),
            mapped_claims=mapped,
            raw_claims=claims,
        )

    def _get_jwks_client(
        self, provider_id: str, provider: TrustedIdP
    ) -> jwt.PyJWKClient:
        """Lazy-create and cache a PyJWKClient for the given provider."""
        if provider_id not in self._jwks_clients:
            self._jwks_clients[provider_id] = jwt.PyJWKClient(
                provider.jwks_uri, cache_jwk_set=True, lifespan=300
            )
        return self._jwks_clients[provider_id]


def _map_claims(
    raw_claims: dict[str, Any], mapping: dict[str, str]
) -> dict[str, Any]:
    """Apply a claim_mapping to raw OIDC claims.

    mapping keys are VC claim names, values are OIDC claim names.
    Only mapped claims that are present in the token are included.
    """
    result: dict[str, Any] = {}
    for vc_claim, oidc_claim in mapping.items():
        value = raw_claims.get(oidc_claim)
        if value is not None:
            result[vc_claim] = value
    return result
