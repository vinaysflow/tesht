"""Tests for gateway.auth."""
from gateway.auth import GatewayAuth
from gateway.config import AuthSettings, GatewayConfig, TrustConfig, UpstreamServer


class TestGatewayAuth:
    def test_blended_vp_extracts_both_identities(
        self, alice, bot, gateway_identity, blended_vp, gateway_config
    ):
        auth = GatewayAuth(gateway_config, gateway_identity=gateway_identity)
        result = auth.authenticate(f"Bearer {blended_vp}")

        assert result.authenticated is True
        assert result.blended is True
        a, _ = alice
        b, _ = bot
        assert result.agent_did == b.did
        assert result.delegator_did == a.did
        assert result.delegator_claims.get("name") == "Alice"
        assert "read_data" in result.effective_scope.get("actions", [])
        assert result.auth_latency_ms > 0

    def test_auth_latency_under_10ms(
        self, gateway_identity, blended_vp, gateway_config
    ):
        auth = GatewayAuth(gateway_config, gateway_identity=gateway_identity)
        result = auth.authenticate(f"Bearer {blended_vp}")
        assert result.auth_latency_ms < 10.0

    def test_missing_delegator_identity_when_required(
        self, bot, delegation, gateway_identity
    ):
        b, _ = bot
        from pramana.credentials import create_presentation
        vp_no_delegator = create_presentation(
            holder=b, credentials=[delegation],
            audience=gateway_identity.did,
        )
        config = GatewayConfig(
            auth=AuthSettings(
                require_delegation=True,
                require_delegator_identity=True,
            ),
        )
        auth = GatewayAuth(config, gateway_identity=gateway_identity)
        result = auth.authenticate(f"Bearer {vp_no_delegator}")
        assert result.authenticated is False
        assert "Delegator identity required" in (result.reason or "")

    def test_no_auth_header_rejected(self, gateway_identity, gateway_config):
        auth = GatewayAuth(gateway_config, gateway_identity=gateway_identity)
        result = auth.authenticate("")
        assert result.authenticated is False

    def test_garbage_token_rejected(self, gateway_identity, gateway_config):
        auth = GatewayAuth(gateway_config, gateway_identity=gateway_identity)
        result = auth.authenticate("Bearer not.a.valid.jwt")
        assert result.authenticated is False

    def test_credential_types_populated(
        self, gateway_identity, blended_vp, gateway_config
    ):
        auth = GatewayAuth(gateway_config, gateway_identity=gateway_identity)
        result = auth.authenticate(f"Bearer {blended_vp}")
        assert "DelegationCredential" in result.credential_types
        assert "OrganizationalRoleCredential" in result.credential_types
        assert "AgentCredential" in result.credential_types
