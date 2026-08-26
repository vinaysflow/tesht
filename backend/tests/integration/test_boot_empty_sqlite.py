import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def test_boot_on_empty_sqlite(tmp_path):
    # Snapshot global state because this test needs a clean import.
    orig_env = os.environ.copy()
    orig_modules = sys.modules.copy()
    orig_sys_path = list(sys.path)

    try:
        db_file = tmp_path / 'empty.db'
        os.environ['DATABASE_URL'] = f"sqlite:///{db_file}"
        os.environ['AUTH_JWT_SECRET'] = 'test-secret'
        os.environ['AUTH_JWT_ISSUER'] = 'tesht-test'

        # Force reload of backend modules for this isolated boot
        for name in list(sys.modules.keys()):
            if name == 'main' or name.startswith('core.') or name == 'core' or name.startswith('models.') or name == 'models' or name.startswith('api.') or name == 'api':
                del sys.modules[name]

        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

        import main  # noqa

        with TestClient(main.app) as c:
            from core.auth.jwt_auth import issue_admin_token

            token = issue_admin_token(scopes=['agents:create'], subject='boot')
            r = c.post('/v1/agents', json={'name': 'boot-agent'}, headers={'Authorization': f'Bearer {token}'})
            assert r.status_code == 200

    finally:
        # Restore global interpreter state for subsequent tests.
        os.environ.clear()
        os.environ.update(orig_env)

        sys.modules.clear()
        sys.modules.update(orig_modules)

        sys.path[:] = orig_sys_path
