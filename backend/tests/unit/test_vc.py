import uuid

import jwt

from core.vc import issue_vc_jwt
from core.settings import settings
from core.status_list import get_or_create_default_list, allocate_index


def test_issue_vc_jwt_contains_required_claims(client, authz_headers):
    issuer = client.post('/v1/agents', json={'name': 'issuer-vc'}, headers=authz_headers).json()

    sl = get_or_create_default_list()
    idx = allocate_index(sl.id)
    status_list_url = f"{settings.tesht_scheme}://127.0.0.1:8000/v1/status/{sl.id}"

    token, jti, iat, exp = issue_vc_jwt(
        issuer_agent_id=uuid.UUID(issuer['id']),
        subject_did='did:web:example.com:subject:123',
        credential_type='AgentCredential',
        status_list_url=status_list_url,
        status_list_index=idx,
        ttl_seconds=3600,
        extra_claims={'capability': 'read_data'},
    )

    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload['iss'].startswith('did:web:')
    assert payload['sub'] == 'did:web:example.com:subject:123'
    assert payload['jti'] == jti
    assert payload['iat'] == iat
    assert payload.get('exp') == exp
