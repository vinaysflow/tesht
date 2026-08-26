from tesht.client import TeshtClient
from tesht.identity import AgentIdentity, resolve_did_key
from tesht.credentials import (
    issue_vc,
    verify_vc,
    create_presentation,
    verify_presentation,
    create_blended_presentation,
    verify_blended_presentation,
    BlendedIdentityResult,
    VerificationResult,
    PresentationResult,
)
from tesht.delegation import (
    issue_delegation,
    delegate_further,
    verify_delegation_chain,
    ScopeEscalationError,
    DelegationResult,
)
from tesht.commerce import (
    issue_intent_mandate,
    issue_cart_mandate,
    verify_mandate,
    MandateVerification,
)

__version__ = "0.3.0"

__all__ = [
    "TeshtClient",
    "AgentIdentity",
    "resolve_did_key",
    "issue_vc",
    "verify_vc",
    "create_presentation",
    "verify_presentation",
    "create_blended_presentation",
    "verify_blended_presentation",
    "BlendedIdentityResult",
    "VerificationResult",
    "PresentationResult",
    "issue_delegation",
    "delegate_further",
    "verify_delegation_chain",
    "ScopeEscalationError",
    "DelegationResult",
    "issue_intent_mandate",
    "issue_cart_mandate",
    "verify_mandate",
    "MandateVerification",
    "__version__",
]
