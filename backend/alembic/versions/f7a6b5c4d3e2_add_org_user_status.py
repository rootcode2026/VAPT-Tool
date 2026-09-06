"""add organization and user status

Revision ID: f7a6b5c4d3e2
Revises: c9e8f4a7e1d3
Create Date: 2026-09-07

Add organization status (active/suspended/archived) and user status (active/suspended)
for Super Admin organization/user administration (Phase 7B). No data deletion.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "f7a6b5c4d3e2"
down_revision: Union[str, Sequence[str], None] = "c9e8f4a7e1d3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Organizations: status + created_at
    op.add_column(
        "organizations",
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
    )
    op.create_index("ix_organizations_status", "organizations", ["status"], unique=False)
    op.add_column(
        "organizations",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # Users: status + created_at
    op.add_column(
        "users",
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
    )
    op.create_index("ix_users_status", "users", ["status"], unique=False)
    op.add_column(
        "users",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_column("users", "created_at")
    op.drop_index("ix_users_status", table_name="users")
    op.drop_column("users", "status")
    op.drop_column("organizations", "created_at")
    op.drop_index("ix_organizations_status", table_name="organizations")
    op.drop_column("organizations", "status")
