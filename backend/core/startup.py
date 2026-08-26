from __future__ import annotations

import os
from urllib.parse import urlparse

from sqlalchemy import text

from core.db import engine
from core.settings import settings
from models import Base


def _strict_migrations() -> bool:
    return settings.env.lower() in {"prod", "production"} or bool(settings.migrations_strict)


def _try_alembic_upgrade() -> bool:
    # Test hook to force failure. Only honored in prod/test modes so a dev/demo
    # deployment can't be accidentally bricked by leaving this env var set.
    if os.getenv('FORCE_ALEMBIC_FAIL', '').lower() in {'1', 'true', 'yes'}:
        if os.getenv('ENV', 'dev').lower() in {'prod', 'production', 'test'}:
            return False

    try:
        from alembic import command
        from alembic.config import Config

        here = os.path.dirname(__file__)
        backend_dir = os.path.abspath(os.path.join(here, ".."))

        cfg = Config(os.path.join(backend_dir, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(backend_dir, "migrations"))
        cfg.set_main_option("sqlalchemy.url", str(settings.database_url))

        command.upgrade(cfg, "head")
        return True
    except Exception:
        return False


def _try_alembic_stamp_head() -> bool:
    """Best-effort: mark the DB at Alembic head without running migrations.

    Used in dev/demo fallback paths where we created schema via create_all().
    """
    try:
        from alembic import command
        from alembic.config import Config

        here = os.path.dirname(__file__)
        backend_dir = os.path.abspath(os.path.join(here, ".."))

        cfg = Config(os.path.join(backend_dir, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(backend_dir, "migrations"))
        cfg.set_main_option("sqlalchemy.url", str(settings.database_url))

        command.stamp(cfg, "head")
        return True
    except Exception:
        return False


def init_db() -> None:
    """Initialize schema.

    - In strict mode (prod): Alembic must succeed.
    - In dev: Alembic preferred; fallback to create_all for resilience.
    """
    ok = _try_alembic_upgrade()

    if not ok:
        if _strict_migrations():
            raise RuntimeError("Database migrations failed (strict mode)")
        # In demo sqlite, a partial Alembic run can leave a broken schema
        # (create_all won't add missing columns). Prefer wiping the sqlite file and recreating.
        db_url = str(settings.database_url)
        if settings.demo_mode and db_url.startswith("sqlite:////"):
            try:
                parsed = urlparse(db_url)
                if parsed.path:
                    os.remove(parsed.path)
            except Exception:
                pass

        Base.metadata.create_all(bind=engine)
        # Ensure /ready passes and future upgrades don't re-run create_table().
        _try_alembic_stamp_head()

    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))

    # Warm JTI dedup cache from DB so replay protection survives restarts
    try:
        from core.jti_dedup import warm_jti_cache
        warm_jti_cache()
    except Exception:
        import logging as _logging
        _logging.getLogger(__name__).debug("JTI cache warm skipped", exc_info=True)

    if settings.demo_mode and settings.demo_auto_seed:
        try:
            from core.seed import seed_tenant
            import logging as _logging
            _log = _logging.getLogger(__name__)
            result = seed_tenant("default", settings.demo_seed_profile)
            if result.agents > 0:
                _log.info(
                    "Auto-seeded: %d agents, %d credentials, %d audit events",
                    result.agents, result.credentials, result.audit_events,
                )
        except Exception:
            import logging as _logging
            _logging.getLogger(__name__).warning("Auto-seed failed", exc_info=True)
