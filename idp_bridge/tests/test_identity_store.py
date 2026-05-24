"""Tests for HumanIdentityStore."""
from __future__ import annotations

import pytest

from idp_bridge.identity_store import HumanIdentityStore

ISSUER = "https://mock-idp.pramana.local"


class TestHumanIdentityStore:
    def test_get_or_create_new_identity(self):
        store = HumanIdentityStore()
        identity, created = store.get_or_create(ISSUER, "sub-001", "Alice")
        assert created is True
        assert identity is not None
        assert identity.did.startswith("did:key:")

    def test_get_or_create_idempotent(self):
        store = HumanIdentityStore()
        id1, created1 = store.get_or_create(ISSUER, "sub-002", "Alice")
        id2, created2 = store.get_or_create(ISSUER, "sub-002", "Alice")
        assert created1 is True
        assert created2 is False
        assert id1.did == id2.did

    def test_different_users_get_different_dids(self):
        store = HumanIdentityStore()
        alice, _ = store.get_or_create(ISSUER, "sub-alice", "Alice")
        bob, _ = store.get_or_create(ISSUER, "sub-bob", "Bob")
        assert alice.did != bob.did

    def test_get_returns_none_for_unknown(self):
        store = HumanIdentityStore()
        result = store.get(ISSUER, "nobody")
        assert result is None

    def test_get_returns_stored_identity(self):
        store = HumanIdentityStore()
        created, _ = store.get_or_create(ISSUER, "sub-charlie", "Charlie")
        fetched = store.get(ISSUER, "sub-charlie")
        assert fetched is not None
        assert fetched.did == created.did

    def test_same_sub_different_issuer_different_identity(self):
        store = HumanIdentityStore()
        id_okta, _ = store.get_or_create("https://okta.example.com", "sub-xyz", "User")
        id_google, _ = store.get_or_create("https://accounts.google.com", "sub-xyz", "User")
        assert id_okta.did != id_google.did

    def test_len_tracks_count(self):
        store = HumanIdentityStore()
        assert len(store) == 0
        store.get_or_create(ISSUER, "s1", "U1")
        assert len(store) == 1
        store.get_or_create(ISSUER, "s2", "U2")
        assert len(store) == 2
        store.get_or_create(ISSUER, "s1", "U1")  # idempotent
        assert len(store) == 2
