from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure backend/ is on sys.path so imports like `core`, `models`, `main` work.
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

# IMPORTANT: tests import `core.*` at module-import time.
DEFAULT_SQLITE_FILE = os.getenv("TESHT_TEST_SQLITE_FILE", "/tmp/tesht_pytest.db")
DEFAULT_TEST_DB_URL = os.getenv("TESHT_TEST_DATABASE_URL") or f"sqlite:///{DEFAULT_SQLITE_FILE}"
os.environ.setdefault("DATABASE_URL", DEFAULT_TEST_DB_URL)
os.environ.setdefault("AUTH_JWT_SECRET", "test-secret")
os.environ.setdefault("AUTH_JWT_ISSUER", "tesht-test")
os.environ.setdefault("TESHT_DEV_MODE", "false")

import core.auth.jwt_auth as jwt_auth


def _purge_modules():
    for name in list(sys.modules.keys()):
        if name in {"main"} or name.startswith("core.") or name == "core" or name.startswith("models.") or name == "models" or name.startswith("api.") or name == "api":
            del sys.modules[name]


def pytest_sessionstart(session):
    # Ensure schema exists even for unit tests that don't use the FastAPI client fixture.
    import importlib

    _purge_modules()

    import core.settings as settings_mod
    importlib.reload(settings_mod)

    import core.db as db_mod
    importlib.reload(db_mod)

    import models as models_mod
    importlib.reload(models_mod)

    models_mod.Base.metadata.create_all(bind=db_mod.engine)


@pytest.fixture(scope="session")
def database_url() -> str:
    return os.environ["DATABASE_URL"]


@pytest.fixture(scope="session")
def app(database_url: str):
    os.environ.setdefault(
        "ALLOWED_ORIGINS",
        "http://127.0.0.1:6080,http://localhost:6080,http://127.0.0.1:8000,http://localhost:8000",
    )

    import importlib

    _purge_modules()

    import core.settings as settings_mod
    importlib.reload(settings_mod)

    import core.db as db_mod
    importlib.reload(db_mod)

    import models as models_mod
    importlib.reload(models_mod)

    import main as main_mod
    importlib.reload(main_mod)

    # Clean schema for app-based tests
    models_mod.Base.metadata.drop_all(bind=db_mod.engine)
    models_mod.Base.metadata.create_all(bind=db_mod.engine)

    return main_mod.app


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def authz_headers():
    token = jwt_auth.issue_admin_token(scopes=["agents:create", "credentials:issue", "credentials:revoke"], subject="test")
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture()
def authz_headers_agents(authz_headers):
    # alias for readability
    return authz_headers

@pytest.fixture()
def authz_headers_issue(authz_headers):
    return authz_headers

@pytest.fixture()
def authz_headers_revoke(authz_headers):
    return authz_headers
