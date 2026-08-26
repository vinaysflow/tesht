
import core.auth.jwt_auth as jwt_auth


def _hdr(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_tenants_cannot_use_each_others_issuer_agent(client):
    t_demo = jwt_auth.issue_admin_token(scopes=["agents:create", "credentials:issue"], tenant_id="demo")
    t_acme = jwt_auth.issue_admin_token(scopes=["agents:create", "credentials:issue"], tenant_id="acme")

    demo_issuer = client.post('/v1/agents', json={'name': 'demo-issuer'}, headers=_hdr(t_demo)).json()

    # Attempt to issue using demo issuer but acme tenant token -> 404
    r = client.post(
        '/v1/credentials/issue',
        headers=_hdr(t_acme),
        json={
            'issuer_agent_id': demo_issuer['id'],
            'subject_did': 'did:web:example.com:subject:123',
            'credential_type': 'AgentCredential',
        },
    )
    assert r.status_code == 404
