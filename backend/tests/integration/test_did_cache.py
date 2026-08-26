"""Tests for the DID resolution LRU cache in core.resolver."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def clear_cache():
    """Ensure the DID cache is empty before and after each test."""
    import core.resolver as resolver_mod
    resolver_mod.flush_cache()
    yield
    resolver_mod.flush_cache()


def _make_did_doc(did: str) -> dict:
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [],
    }


def _mock_response(did: str):
    resp = MagicMock()
    resp.json.return_value = _make_did_doc(did)
    resp.raise_for_status.return_value = None
    return resp


# ── Cache behaviour tests ─────────────────────────────────────────────────────

def test_cache_hit_avoids_fetch():
    """Resolving the same external DID twice should only trigger one HTTP call."""
    did = "did:web:example.com"

    with patch("core.resolver.httpx.get", return_value=_mock_response(did)) as mock_get:
        import core.resolver as resolver_mod

        doc1 = resolver_mod.resolve_did(did)
        doc2 = resolver_mod.resolve_did(did)

    assert doc1 == doc2
    assert mock_get.call_count == 1, "Second resolve should be served from cache"


def test_cache_ttl_expiry():
    """After the TTL expires the cache must be bypassed and a fresh fetch issued."""
    did = "did:web:example.com"

    with patch("core.resolver.httpx.get", return_value=_mock_response(did)) as mock_get:
        import core.resolver as resolver_mod
        import core.settings as settings_mod

        original_ttl = settings_mod.settings.did_cache_ttl_seconds
        try:
            # Set a very short TTL so we can expire it without sleeping
            settings_mod.settings.did_cache_ttl_seconds = 0

            # First resolve — populates cache
            resolver_mod.resolve_did(did)

            # TTL is 0 so any subsequent call finds the entry expired
            resolver_mod.resolve_did(did)
        finally:
            settings_mod.settings.did_cache_ttl_seconds = original_ttl

    assert mock_get.call_count == 2, "Expired cache entry must trigger a fresh HTTP fetch"


def test_cache_flush():
    """Flushing the cache should force a new HTTP call on the next resolve."""
    did = "did:web:example.com"

    with patch("core.resolver.httpx.get", return_value=_mock_response(did)) as mock_get:
        import core.resolver as resolver_mod

        resolver_mod.resolve_did(did)
        resolver_mod.flush_cache()
        resolver_mod.resolve_did(did)

    assert mock_get.call_count == 2, "Post-flush resolve must trigger a fresh HTTP fetch"


# ── PostgreSQL enforcement test ───────────────────────────────────────────────

def test_postgres_enforcement():
    """Settings must raise ValueError when ENV=production and DATABASE_URL is SQLite."""
    import os
    import sys

    env_overrides = {
        "ENV": "production",
        "DATABASE_URL": "sqlite:////tmp/tesht_test.db",
        "AUTH_JWT_SECRET": "test-secret",
        "AUTH_JWT_ISSUER": "tesht-test",
    }

    original_env = {k: os.environ.get(k) for k in env_overrides}
    # Remove DATABASE_URL from cache so _default_database_url isn't called
    original_env.setdefault("DATABASE_URL", None)

    try:
        os.environ.update(env_overrides)

        # Remove cached module so the next import re-runs the module body fresh.
        # We expect Settings() at module scope to raise ValidationError wrapping our ValueError.
        for mod in list(sys.modules):
            if mod in ("core.settings", "core") or mod.startswith("core."):
                del sys.modules[mod]

        from pydantic import ValidationError as PydanticValidationError

        with pytest.raises((ValueError, PydanticValidationError)):
            import core.settings  # noqa: F401  — module-level Settings() will raise
    finally:
        for k, v in original_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        # Purge the (possibly broken) module cache so later tests get a clean settings
        for mod in list(sys.modules):
            if mod in ("core.settings", "core") or mod.startswith("core."):
                del sys.modules[mod]
