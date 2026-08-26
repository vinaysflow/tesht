from __future__ import annotations

import uuid

from core.crypto import encrypt_text
from core.db import db_session
from core.did import generate_ed25519_keypair
from core.settings import settings
from models import Agent, Key

STATUS_ISSUER_NAME = "__status_list_issuer__"


def status_issuer_did() -> str:
    # Keep issuer DID stable and simple: did:web:<domain>
    return f"did:web:{settings.tesht_domain}"


def ensure_status_issuer() -> tuple[Agent, Key]:
    did = status_issuer_did()

    with db_session() as db:
        agent = db.query(Agent).filter(Agent.did == did).one_or_none()
        if agent is None:
            agent = Agent(id=uuid.uuid4(), name=STATUS_ISSUER_NAME, did=did)
            db.add(agent)
            db.flush()

        key = (
            db.query(Key)
            .filter(Key.agent_id == agent.id)
            .order_by(Key.created_at.desc())
            .first()
        )

        if key is None:
            private_pem, public_jwk, _ = generate_ed25519_keypair()
            kid = f"{did}#key-1"
            key = Key(
                agent_id=agent.id,
                kid=kid,
                public_jwk=public_jwk,
                private_key_enc=encrypt_text(private_pem),
            )
            db.add(key)

        db.commit()
        db.refresh(agent)
        db.refresh(key)

    return agent, key
