from __future__ import annotations

import argparse
import json
import sys
import os

# Ensure backend root is on sys.path when run as a script
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..")))
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import unquote, urlparse

import httpx
import jwt

from core.bitstring_encoding import b64url_decode, gzip_decompress
from core.did import public_key_from_jwk


def _did_web_to_url(did: str) -> str:
    if not did.startswith('did:web:'):
        raise ValueError('only did:web supported')

    parts = did.split(':')
    if len(parts) < 3:
        raise ValueError('invalid did:web')

    domain = unquote(parts[2])
    path_segments = [unquote(p) for p in parts[3:]]
    if not path_segments:
        return f"https://{domain}/.well-known/did.json"

    path = '/'.join(path_segments)
    return f"https://{domain}/{path}/did.json"


def _fetch_json(url: str, *, timeout: float) -> dict[str, Any]:
    r = httpx.get(url, timeout=timeout, headers={'accept': 'application/json'})
    r.raise_for_status()
    return r.json()


def _resolve_did_http(did: str, *, timeout: float) -> dict[str, Any]:
    url = _did_web_to_url(did)
    # If did:web includes an explicit scheme in its domain (like localhost:5051), we want http.
    # did:web has no scheme, so we treat localhost/dev as http by default.
    parsed = urlparse(url)
    if parsed.hostname in {'localhost', '127.0.0.1'}:
        url = url.replace('https://', 'http://', 1)
    return _fetch_json(url, timeout=timeout)


def _select_vm(did_doc: dict[str, Any], kid: Optional[str]) -> dict[str, Any]:
    vms = did_doc.get('verificationMethod') or []
    if not isinstance(vms, list):
        raise ValueError('invalid did doc: verificationMethod')

    if kid:
        for m in vms:
            if isinstance(m, dict) and m.get('id') == kid:
                return m

    for m in vms:
        if isinstance(m, dict):
            return m

    raise ValueError('no verification method')


def _verify_ed25519_jwt(token: str, *, timeout: float) -> dict[str, Any]:
    header = jwt.get_unverified_header(token)
    kid = header.get('kid')

    payload = jwt.decode(token, options={'verify_signature': False})
    iss = payload.get('iss')
    if not isinstance(iss, str):
        raise ValueError('missing iss')

    did_doc = _resolve_did_http(iss, timeout=timeout)
    vm = _select_vm(did_doc, kid)
    jwk = vm.get('publicKeyJwk')
    if not isinstance(jwk, dict):
        raise ValueError('missing publicKeyJwk')

    pub = public_key_from_jwk(jwk)
    verified = jwt.decode(token, key=pub, algorithms=['EdDSA'])
    return verified


def _fetch_and_verify_status_list(status_list_url: str, *, timeout: float) -> bytes:
    data = _fetch_json(status_list_url, timeout=timeout)
    status_jwt = data.get('jwt')
    if not isinstance(status_jwt, str):
        raise ValueError('status endpoint missing jwt')

    verified = _verify_ed25519_jwt(status_jwt, timeout=timeout)
    vc = verified.get('vc')
    if not isinstance(vc, dict):
        raise ValueError('status list missing vc')
    cs = vc.get('credentialSubject')
    if not isinstance(cs, dict):
        raise ValueError('status list missing credentialSubject')
    encoded_list = cs.get('encodedList')
    if not isinstance(encoded_list, str):
        raise ValueError('status list missing encodedList')

    raw = gzip_decompress(b64url_decode(encoded_list))
    return raw


@dataclass
class VerifyResult:
    verified: bool
    revoked: bool
    reason: Optional[str]
    payload: dict[str, Any]


def verify_vc(token: str, *, timeout: float) -> VerifyResult:
    verified_payload = _verify_ed25519_jwt(token, timeout=timeout)
    vc = verified_payload.get('vc') or {}
    cs = vc.get('credentialStatus') or {}

    status_list_url = cs.get('statusListCredential')
    status_list_index = cs.get('statusListIndex')

    revoked = False
    if isinstance(status_list_url, str) and status_list_index is not None:
        raw = _fetch_and_verify_status_list(status_list_url, timeout=timeout)
        idx = int(status_list_index)
        if idx < 0 or idx >= (len(raw) * 8):
            revoked = False
        else:
            byte_i = idx // 8
            bit_i = idx % 8
            revoked = (raw[byte_i] & (1 << bit_i)) != 0

    if revoked:
        return VerifyResult(verified=False, revoked=True, reason='revoked', payload=verified_payload)

    return VerifyResult(verified=True, revoked=False, reason=None, payload=verified_payload)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description='Tesht portable VC verifier (no DB)')
    ap.add_argument('--jwt', dest='jwt', help='VC JWT (EdDSA)', required=False)
    ap.add_argument('--timeout', dest='timeout', type=float, default=10.0)
    args = ap.parse_args(argv)

    token = args.jwt
    if not token:
        token = sys.stdin.read().strip()

    try:
        res = verify_vc(token, timeout=args.timeout)
        out = {
            'verified': res.verified,
            'revoked': res.revoked,
            'reason': res.reason,
            'iss': res.payload.get('iss'),
            'sub': res.payload.get('sub'),
            'jti': res.payload.get('jti'),
        }
        print(json.dumps(out))
        return 0
    except Exception as e:
        print(json.dumps({'verified': False, 'error': str(e)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
