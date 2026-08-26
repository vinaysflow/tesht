"""
tesht.integrations.langchain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
LangChain integration for Tesht agent identity.

``langchain-core`` is an OPTIONAL dependency.  This module imports it
conditionally so that the rest of the Tesht SDK works even when
LangChain is not installed.
"""
from __future__ import annotations

from typing import Any, Optional

import jwt as pyjwt

from tesht.credentials import create_presentation, create_blended_presentation, verify_vc
from tesht.identity import AgentIdentity

# ---------------------------------------------------------------------------
# Optional langchain-core import
# ---------------------------------------------------------------------------

try:
    from langchain_core.tools import BaseTool  # type: ignore[import]
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    BaseTool = object  # type: ignore[misc,assignment]


# ---------------------------------------------------------------------------
# Error
# ---------------------------------------------------------------------------

class LangChainNotInstalled(ImportError):
    def __init__(self) -> None:
        super().__init__(
            "LangChain is required for this feature. "
            "Install with: pip install langchain-core"
        )


# ---------------------------------------------------------------------------
# TeshtAgentContext — no LangChain dependency
# ---------------------------------------------------------------------------

class TeshtAgentContext:
    """Provides Tesht identity context to a LangChain (or any) agent."""

    def __init__(
        self,
        identity: AgentIdentity,
        credentials: Optional[list[str]] = None,
    ) -> None:
        self.identity = identity
        self.credentials: list[str] = credentials or []

    def get_system_prompt_addition(self) -> str:
        """
        Return a string to append to the agent's system prompt, informing it
        of its verifiable identity and held credentials.
        """
        did = self.identity.did

        # Extract credential types from VC-JWTs without signature verification
        cred_types: list[str] = []
        has_delegation = False
        for vc_jwt in self.credentials:
            try:
                payload = pyjwt.decode(vc_jwt, options={"verify_signature": False})
                vc = payload.get("vc") or {}
                types = vc.get("type") or []
                # Second entry is the specific type (first is always "VerifiableCredential")
                specific = types[1] if len(types) > 1 else types[0] if types else None
                if specific and specific not in cred_types:
                    cred_types.append(specific)
                if specific == "DelegationCredential":
                    has_delegation = True
            except Exception:
                continue

        count = len(self.credentials)
        if cred_types:
            cred_summary = f"{count} verifiable credential{'s' if count != 1 else ''}: {', '.join(cred_types)}"
        else:
            cred_summary = f"{count} verifiable credential{'s' if count != 1 else ''}"

        base = (
            f"You have a verifiable digital identity (DID: {did}). "
            f"When interacting with other agents or services, you can present "
            f"your credentials to prove your identity and capabilities. "
            f"You hold {cred_summary}."
        )
        if has_delegation:
            base += (
                " You hold a delegation credential that lets you act on behalf of a human "
                "delegator. When calling MCP servers that require blended identity, use "
                "get_blended_auth_headers() to bundle your delegation with the delegator's "
                "identity into a single Verifiable Presentation."
            )
        return base

    def get_auth_headers(self, audience: str) -> dict[str, str]:
        """
        Return an Authorization header dict for making authenticated requests.

        Creates a VP addressed to ``audience`` (must be a DID) and wraps it
        as a Bearer token.
        """
        if not self.credentials:
            raise ValueError(
                "No credentials in context. Add credentials before calling get_auth_headers()."
            )
        vp_jwt = create_presentation(
            holder=self.identity,
            credentials=self.credentials,
            audience=audience,
        )
        return {"Authorization": f"Bearer {vp_jwt}"}

    def get_blended_auth_headers(
        self,
        audience: str,
        delegation_jwt: str,
        delegator_identity_jwt: Optional[str] = None,
    ) -> dict[str, str]:
        """
        Return an Authorization header containing a Blended Identity VP.

        Bundles the delegation credential, optionally the delegator's identity
        credential, and any additional credentials held by the agent into a
        single VP-JWT of type ``BlendedIdentityPresentation``.

        Args:
            audience:               Target MCP server's DID.
            delegation_jwt:         A DelegationCredential VC-JWT.
            delegator_identity_jwt: Optional identity credential of the human delegator.

        Returns:
            {"Authorization": "Bearer <blended-VP-JWT>"}
        """
        vp_jwt = create_blended_presentation(
            agent=self.identity,
            delegation_jwt=delegation_jwt,
            delegator_identity_jwt=delegator_identity_jwt,
            additional_credentials=self.credentials if self.credentials else None,
            audience=audience,
        )
        return {"Authorization": f"Bearer {vp_jwt}"}


# ---------------------------------------------------------------------------
# TeshtVerifierTool — requires langchain-core
# ---------------------------------------------------------------------------

class TeshtVerifierTool(BaseTool):  # type: ignore[misc]
    """LangChain tool for verifying AI agent credentials."""

    name: str = "verify_agent_credential"
    description: str = (
        "Verify an AI agent's identity and credentials. "
        "Input: a VC-JWT string (a long base64-encoded token). "
        "Output: verification result including agent DID, credential type, and trust status."
    )

    def __init__(self, **kwargs: Any) -> None:
        if not HAS_LANGCHAIN:
            raise LangChainNotInstalled()
        super().__init__(**kwargs)

    def _run(self, vc_jwt: str) -> str:
        """Verify the credential and return a human-readable result."""
        result = verify_vc(vc_jwt)
        if result.verified:
            return (
                f"VERIFIED: Agent {result.issuer_did} issued a valid "
                f"{result.credential_type} credential to {result.subject_did}."
            )
        return f"FAILED: Credential verification failed. Reason: {result.reason}"

    async def _arun(self, vc_jwt: str) -> str:  # type: ignore[override]
        """Async version — delegates to synchronous _run."""
        return self._run(vc_jwt)
