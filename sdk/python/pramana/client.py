from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import httpx


@dataclass
class PramanaClient:
    """HTTP client for the Pramana Protocol server API.

    Supports classic credential APIs plus the Session authorization runtime:
    Session / Decision / Mandate.
    """

    base_url: str = "http://localhost:8000"
    token: Optional[str] = None
    timeout: float = 20.0

    def _headers(self, idempotency_key: Optional[str] = None) -> dict[str, str]:
        headers: dict[str, str] = {"content-type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    # ── Agents / credentials (legacy surface) ──────────────────────────

    def create_agent(self, name: str) -> dict[str, Any]:
        return self._post("/v1/agents", {"name": name})

    def issue_credential(
        self,
        issuer_agent_id: str,
        subject_did: str,
        credential_type: str = "AgentCredential",
        ttl_seconds: Optional[int] = None,
        subject_claims: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "issuer_agent_id": issuer_agent_id,
            "subject_did": subject_did,
            "credential_type": credential_type,
        }
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        if subject_claims is not None:
            body["subject_claims"] = subject_claims
        return self._post("/v1/credentials/issue", body)

    def verify_credential(self, jwt: str) -> dict[str, Any]:
        return self._post("/v1/credentials/verify", {"jwt": jwt})

    def revoke_credential(self, credential_id: str) -> dict[str, Any]:
        return self._post(f"/v1/credentials/{credential_id}/revoke", {})

    # ── Session (authorization runtime) ────────────────────────────────

    def create_session(
        self,
        *,
        agent_did: str,
        human_did: Optional[str] = None,
        human_proof_jwt: Optional[str] = None,
        agent_vc_jwt: Optional[str] = None,
        delegation_jwt: Optional[str] = None,
        scope: Optional[dict[str, Any]] = None,
        packs: Optional[list[str]] = None,
        ttl_seconds: int = 3600,
        metadata: Optional[dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create a Session (human→agent handoff)."""
        body: dict[str, Any] = {
            "agent_did": agent_did,
            "scope": scope or {},
            "packs": packs or ["core"],
            "ttl_seconds": ttl_seconds,
            "metadata": metadata or {},
        }
        if human_did is not None:
            body["human_did"] = human_did
        if human_proof_jwt is not None:
            body["human_proof_jwt"] = human_proof_jwt
        if agent_vc_jwt is not None:
            body["agent_vc_jwt"] = agent_vc_jwt
        if delegation_jwt is not None:
            body["delegation_jwt"] = delegation_jwt
        return self._post("/v1/sessions", body, idempotency_key=idempotency_key)

    def get_session(self, session_id: str) -> dict[str, Any]:
        return self._get(f"/v1/sessions/{session_id}")

    def decide(
        self,
        session_id: str,
        *,
        action: str,
        resource: Optional[str] = None,
        amount: Optional[int] = None,
        currency: Optional[str] = None,
        tool_name: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Evaluate an action → allow | step_up | block (Decision)."""
        body: dict[str, Any] = {"action": action, "metadata": metadata or {}}
        if resource is not None:
            body["resource"] = resource
        if amount is not None:
            body["amount"] = amount
        if currency is not None:
            body["currency"] = currency
        if tool_name is not None:
            body["tool_name"] = tool_name
        return self._post(f"/v1/sessions/{session_id}/actions", body)

    def step_up(
        self,
        session_id: str,
        *,
        human_proof_jwt: Optional[str] = None,
        fresh_vp_jwt: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"metadata": metadata or {}}
        if human_proof_jwt is not None:
            body["human_proof_jwt"] = human_proof_jwt
        if fresh_vp_jwt is not None:
            body["fresh_vp_jwt"] = fresh_vp_jwt
        return self._post(f"/v1/sessions/{session_id}/step_up", body)

    def revoke_session(
        self,
        session_id: str,
        *,
        cascade: bool = True,
        reason: Optional[str] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"cascade": cascade}
        if reason is not None:
            body["reason"] = reason
        return self._post(f"/v1/sessions/{session_id}/revoke", body)

    # ── Mandate (commerce) ─────────────────────────────────────────────

    def create_intent_mandate(
        self,
        *,
        agent_did: str,
        max_amount: int,
        currency: str = "USD",
        intent: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        body = {
            "agent_did": agent_did,
            "intent": {
                "max_amount": max_amount,
                "currency": currency,
                **(intent or {}),
            },
        }
        return self._post("/v1/commerce/mandates/intent", body)

    def create_cart_mandate(
        self,
        *,
        agent_did: str,
        intent_mandate_jwt: str,
        cart: dict[str, Any],
    ) -> dict[str, Any]:
        return self._post(
            "/v1/commerce/mandates/cart",
            {
                "agent_did": agent_did,
                "intent_mandate_jwt": intent_mandate_jwt,
                "cart": cart,
            },
        )

    def verify_mandate(
        self,
        jwt: str,
        mandate_type: Optional[str] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"jwt": jwt}
        if mandate_type:
            body["mandate_type"] = mandate_type
        return self._post("/v1/commerce/mandates/verify", body)

    # ── HTTP helpers ───────────────────────────────────────────────────

    def _post(
        self,
        path: str,
        body: dict[str, Any],
        *,
        idempotency_key: Optional[str] = None,
    ) -> dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(
                self.base_url.rstrip("/") + path,
                json=body,
                headers=self._headers(idempotency_key),
            )
            r.raise_for_status()
            return r.json()

    def _get(self, path: str) -> dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            r = client.get(
                self.base_url.rstrip("/") + path,
                headers=self._headers(),
            )
            r.raise_for_status()
            return r.json()
