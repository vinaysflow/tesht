import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def test_prod_requires_migrations(tmp_path):
    orig_env = os.environ.copy()
    orig_modules = sys.modules.copy()
    orig_sys_path = list(sys.path)

    try:
        db_file = tmp_path / 'strict.db'
        os.environ['DATABASE_URL'] = f"sqlite:///{db_file}"
        os.environ['ENV'] = 'prod'
        os.environ['FORCE_ALEMBIC_FAIL'] = 'true'

        # minimal auth settings to import app
        os.environ['AUTH_JWT_SECRET'] = 'test-secret'
        os.environ['AUTH_JWT_ISSUER'] = 'tesht-test'

        for name in list(sys.modules.keys()):
            if name == 'main' or name.startswith('core.') or name == 'core' or name.startswith('models.') or name == 'models' or name.startswith('api.') or name == 'api':
                del sys.modules[name]

        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

        import main  # noqa

        with pytest.raises(RuntimeError):
            with TestClient(main.app):
                pass

    finally:
        os.environ.clear()
        os.environ.update(orig_env)
        sys.modules.clear()
        sys.modules.update(orig_modules)
        sys.path[:] = orig_sys_path
