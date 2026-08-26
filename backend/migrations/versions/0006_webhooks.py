"""webhooks

Revision ID: 0006_webhooks
Revises: 0005_trust_events
Create Date: 2026-03-06

"""

from alembic import op
import sqlalchemy as sa

revision = "0006_webhooks"
down_revision = "0005_trust_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "webhooks",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=100), nullable=False, server_default="default"),
        sa.Column("url", sa.String(length=2000), nullable=False),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("secret", sa.String(length=200), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index("ix_webhooks_tenant_id", "webhooks", ["tenant_id"], unique=False)
    op.create_index("ix_webhooks_active", "webhooks", ["active"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_webhooks_active", table_name="webhooks")
    op.drop_index("ix_webhooks_tenant_id", table_name="webhooks")
    op.drop_table("webhooks")
