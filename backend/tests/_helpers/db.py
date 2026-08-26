from __future__ import annotations

import os
from urllib.parse import urlparse

import psycopg2


def derive_test_db_url(database_url: str) -> str:
    """Prefer using a separate *_test database so tests don't clobber dev data."""
    u = urlparse(database_url)
    db = (u.path or "").lstrip("/")
    if not db:
        return database_url
    if db.endswith("_test"):
        return database_url
    test_db = f"{db}_test"
    return database_url[: -(len(db))] + test_db


def ensure_test_database(database_url: str) -> str:
    """Best-effort: create the *_test database if credentials allow."""
    test_url = derive_test_db_url(database_url)
    if test_url == database_url:
        return database_url

    # connect to postgres maintenance DB
    u = urlparse(database_url)
    maint_db = os.getenv("TESHT_PG_MAINT_DB", "postgres")
    maint_url = database_url[: -(len((u.path or "").lstrip("/"))) ] + maint_db

    try:
        conn = psycopg2.connect(maint_url)
        conn.autocommit = True
        cur = conn.cursor()
        test_db_name = urlparse(test_url).path.lstrip("/")
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (test_db_name,))
        exists = cur.fetchone() is not None
        if not exists:
            cur.execute(f'CREATE DATABASE "{test_db_name}"')
        cur.close()
        conn.close()
        return test_url
    except Exception:
        # If we can't create it, fall back to the provided URL.
        return database_url
