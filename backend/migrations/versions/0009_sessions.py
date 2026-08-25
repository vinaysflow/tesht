"""Add authorization_sessions table for Session API

Revision ID: 0009_sessions
Revises: 0008_spiffe_agent_id
Create Date: 2026-07-21

"""

from alembic import op
import sqlalchemy as sa

revision = "0009_sessions"
down_revision = "0008_spiffe_agent_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authorization_sessions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("agent_did", sa.String(length=600), nullable=False),
        sa.Column("human_did", sa.String(length=600), nullable=True),
        sa.Column("delegation_jti", sa.String(length=200), nullable=True),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("packs", sa.JSON(), nullable=False),
        sa.Column("proof_bundle", sa.JSON(), nullable=False),
        sa.Column("last_decision", sa.JSON(), nullable=False),
        sa.Column("trust_score", sa.Integer(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=True),
        sa.Column("request_hash", sa.String(length=64), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_authorization_sessions_tenant_id", "authorization_sessions", ["tenant_id"])
    op.create_index("ix_authorization_sessions_status", "authorization_sessions", ["status"])
    op.create_index("ix_authorization_sessions_agent_did", "authorization_sessions", ["agent_did"])
    op.create_index("ix_authorization_sessions_human_did", "authorization_sessions", ["human_did"])
    op.create_index("ix_authorization_sessions_delegation_jti", "authorization_sessions", ["delegation_jti"])
    op.create_index("ix_authorization_sessions_idempotency_key", "authorization_sessions", ["idempotency_key"])


def downgrade() -> None:
    op.drop_index("ix_authorization_sessions_idempotency_key", table_name="authorization_sessions")
    op.drop_index("ix_authorization_sessions_delegation_jti", table_name="authorization_sessions")
    op.drop_index("ix_authorization_sessions_human_did", table_name="authorization_sessions")
    op.drop_index("ix_authorization_sessions_agent_did", table_name="authorization_sessions")
    op.drop_index("ix_authorization_sessions_status", table_name="authorization_sessions")
    op.drop_index("ix_authorization_sessions_tenant_id", table_name="authorization_sessions")
    op.drop_table("authorization_sessions")
