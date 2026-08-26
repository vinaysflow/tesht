import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

import core.auth.jwt_auth as jwt_auth


def _free_port() -> int:
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_http(url: str, timeout_s: float = 10.0):
    import httpx

    start = time.time()
    while time.time() - start < timeout_s:
        try:
            r = httpx.get(url, timeout=1.0)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError('server did not start')


@pytest.mark.e2e
def test_portable_verifier_no_db(tmp_path):
    port = _free_port()
    db_file = tmp_path / 'portable.db'

    env = os.environ.copy()
    env['DATABASE_URL'] = f"sqlite:///{db_file}"
    env['AUTH_JWT_SECRET'] = os.environ.get('AUTH_JWT_SECRET', 'test-secret')
    env['AUTH_JWT_ISSUER'] = os.environ.get('AUTH_JWT_ISSUER', 'tesht-test')
    env['TESHT_DOMAIN'] = f"localhost%3A{port}"
    env['TESHT_SCHEME'] = 'http'

    # Run uvicorn
    proc = subprocess.Popen(
        [sys.executable, '-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', str(port)],
        cwd=str(Path(__file__).resolve().parents[2]),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        _wait_http(f"http://127.0.0.1:{port}/health")

        import httpx

        token = jwt_auth.issue_admin_token(scopes=['agents:create','credentials:issue','credentials:revoke'], tenant_id='demo')
        headers = {'Authorization': f'Bearer {token}'}

        issuer = httpx.post(f"http://127.0.0.1:{port}/v1/agents", json={'name': 'issuer'}, headers=headers, timeout=5.0).json()
        subject = httpx.post(f"http://127.0.0.1:{port}/v1/agents", json={'name': 'subject'}, headers=headers, timeout=5.0).json()

        issued = httpx.post(
            f"http://127.0.0.1:{port}/v1/credentials/issue",
            json={'issuer_agent_id': issuer['id'], 'subject_did': subject['did'], 'credential_type': 'AgentCredential'},
            headers=headers,
            timeout=5.0,
        ).json()

        vc_jwt = issued['jwt']

        # Portable verify (should pass)
        out = subprocess.check_output([sys.executable, 'tools/verifier_cli.py', '--jwt', vc_jwt], cwd=str(Path(__file__).resolve().parents[2]), env=env)
        v = json.loads(out.decode('utf-8'))
        assert v['verified'] is True

        # Revoke
        httpx.post(f"http://127.0.0.1:{port}/v1/credentials/{issued['credential_id']}/revoke", json={}, headers=headers, timeout=5.0)

        out2 = subprocess.check_output([sys.executable, 'tools/verifier_cli.py', '--jwt', vc_jwt], cwd=str(Path(__file__).resolve().parents[2]), env=env)
        v2 = json.loads(out2.decode('utf-8'))
        assert v2['verified'] is False
        assert v2.get('reason') == 'revoked'

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
