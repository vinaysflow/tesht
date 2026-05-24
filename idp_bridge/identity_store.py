"""
idp_bridge.identity_store
~~~~~~~~~~~~~~~~~~~~~~~~~
In-memory store mapping (idp_issuer, oidc_sub) -> AgentIdentity.

This is the demo equivalent of the backend's Agent/Key DB tables.
The SPIFFE bridge analogue is _get_or_create_agent() in
backend/api/routes/spiffe_bridge.py.

For production: replace this with DB-backed storage using the
Agent + Key models and the _get_or_create_agent() pattern.
"""
from __future__ import annotations

import threading
from typing import Optional

from pramana.identity import AgentIdentity


class HumanIdentityStore:
    """Thread-safe in-memory store of platform-managed human identities.

    Each enterprise user gets a stable ``did:key`` identity on first
    attestation.  Subsequent attestations from the same (issuer, sub)
    pair return the same identity without creating a new keypair.
    """

    def __init__(self) -> None:
        self._identities: dict[str, AgentIdentity] = {}
        self._lock = threading.Lock()

    def _key(self, issuer: str, subject: str) -> str:
        return f"{issuer}|{subject}"

    def get_or_create(
        self, issuer: str, subject: str, name: str
    ) -> tuple[AgentIdentity, bool]:
        """Return (identity, was_created).

        If an identity already exists for (issuer, subject), it is returned
        unchanged.  Otherwise a new ``AgentIdentity`` is created and stored.
        """
        k = self._key(issuer, subject)
        with self._lock:
            if k in self._identities:
                return self._identities[k], False
            identity = AgentIdentity.create(name)
            self._identities[k] = identity
            return identity, True

    def get(self, issuer: str, subject: str) -> Optional[AgentIdentity]:
        """Return the stored identity for (issuer, subject), or None."""
        return self._identities.get(self._key(issuer, subject))

    def __len__(self) -> int:
        return len(self._identities)
