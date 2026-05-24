from pramana.client import PramanaClient
from pramana.identity import AgentIdentity, resolve_did_key
from pramana.credentials import (
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
from pramana.delegation import (
    issue_delegation,
    delegate_further,
    verify_delegation_chain,
    ScopeEscalationError,
    DelegationResult,
)
from pramana.commerce import (
    issue_intent_mandate,
    issue_cart_mandate,
    verify_mandate,
    MandateVerification,
)

__version__ = "0.2.0"

__all__ = [
    "PramanaClient",
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
