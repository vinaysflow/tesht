from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Any
from urllib.parse import unquote, urlparse

import jwt
from cryptography.hazmat.primitives import serialization

from core.bitstring_encoding import b64url, b64url_decode, gzip_compress, gzip_decompress
from core.crypto import decrypt_text
from core.db import db_session
from core.did import public_key_from_jwk
from core.resolver import resolve_did
from core.settings import settings
from core.status_issuer import ensure_status_issuer
from models import StatusList


def _now() -> int:
    return int(time.time())


def status_list_url(status_list_id: uuid.UUID) -> str:
    domain = unquote(settings.tesht_domain)
    return f"{settings.tesht_scheme}://{domain}/v1/status/{status_list_id}"


def issue_status_list_vc_jwt(status_list_id: uuid.UUID) -> tuple[str, dict[str, Any]]:
    with db_session() as db:
        sl = db.query(StatusList).filter(StatusList.id == status_list_id).one()

    raw_bits = b64url_decode(sl.bitstring)
    encoded_list = b64url(gzip_compress(raw_bits))

    url = status_list_url(sl.id)
    vc = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/status/v1",
        ],
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "id": url,
        "issuer": None,
        "validFrom": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "credentialSubject": {
            "id": f"{url}#list",
            "type": "BitstringStatusList",
            "statusPurpose": sl.purpose,
            "encodedList": encoded_list,
        },
    }

    issuer_agent, issuer_key = ensure_status_issuer()
    vc["issuer"] = issuer_agent.did

    private_pem = decrypt_text(issuer_key.private_key_enc)
    private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)

    payload = {
        "iss": issuer_agent.did,
        "sub": vc["credentialSubject"]["id"],
        "jti": str(uuid.uuid4()),
        "iat": _now(),
        "vc": vc,
    }

    token = jwt.encode(payload, key=private_key, algorithm="EdDSA", headers={"kid": issuer_key.kid, "typ": "JWT"})
    return token, vc


def verify_and_extract_encoded_list(status_list_jwt: str) -> tuple[bytes, dict[str, Any]]:
    header = jwt.get_unverified_header(status_list_jwt)
    kid = header.get('kid')

    payload = jwt.decode(status_list_jwt, options={'verify_signature': False})

    issuer = payload.get('iss')
    if not issuer:
        raise ValueError('status list missing iss')

    did_doc = resolve_did(issuer)
    vms = did_doc.get('verificationMethod') or []

    vm = None
    if kid:
        for m in vms:
            if m.get('id') == kid:
                vm = m
                break
    if vm is None and vms:
        vm = vms[0]
    if vm is None:
        raise ValueError('no verification method for status list issuer')

    jwk = vm.get('publicKeyJwk')
    pub = public_key_from_jwk(jwk)

    verified_payload = jwt.decode(status_list_jwt, key=pub, algorithms=['EdDSA'])

    vc = verified_payload.get('vc')
    if not isinstance(vc, dict):
        raise ValueError('status list missing vc claim')

    cs = vc.get('credentialSubject')
    if not isinstance(cs, dict):
        raise ValueError('status list missing credentialSubject')

    encoded_list = cs.get('encodedList')
    if not isinstance(encoded_list, str):
        raise ValueError('status list missing encodedList')

    raw = gzip_decompress(b64url_decode(encoded_list))
    return raw, verified_payload


def is_local_status_list_url(url: str) -> bool:
    try:
        u = urlparse(url)
        hostport = u.netloc
        local_hostport = unquote(settings.tesht_domain)
        return hostport == local_hostport and u.path.startswith('/v1/status/')
    except Exception:
        return False


def status_list_id_from_url(url: str) -> uuid.UUID:
    u = urlparse(url)
    parts = u.path.rstrip('/').split('/')
    return uuid.UUID(parts[-1])
