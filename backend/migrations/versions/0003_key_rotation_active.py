"""key active flag

Revision ID: 0003_key_rotation_active
Revises: 0002_tenancy
Create Date: 2025-12-23

"""

from alembic import op
import sqlalchemy as sa

revision = "0003_key_rotation_active"
down_revision = "0002_tenancy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind is not None and bind.dialect.name == "sqlite"

    if is_sqlite:
        # SQLite requires batch mode; keep default to avoid rebuild-on-drop-default.
        with op.batch_alter_table("keys") as batch:
            batch.add_column(sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()))
    else:
        op.add_column("keys", sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()))
        op.alter_column("keys", "active", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind is not None and bind.dialect.name == "sqlite"
    if is_sqlite:
        with op.batch_alter_table("keys") as batch:
            batch.drop_column("active")
    else:
        op.drop_column("keys", "active")
