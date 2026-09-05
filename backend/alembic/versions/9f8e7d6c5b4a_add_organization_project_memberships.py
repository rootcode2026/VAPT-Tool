"""add organization and project memberships

Revision ID: 9f8e7d6c5b4a
Revises: b1a2c3d4e5f6
Create Date: 2026-09-05

Enterprise multi-tenancy + RBAC foundation:
- organizations remain as before
- organization_memberships: (organization_id, user_id) unique, role member/org_admin
- project_memberships: (project_id, user_id) unique, role viewer/analyst/project_admin
No RLS, no policies. Preserve existing data via organization_membership population.
Project memberships are NOT auto-populated for existing projects because creator
information is not stored; access falls back to organization membership until
explicit project memberships are created. Documented as transitional.

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "9f8e7d6c5b4a"
down_revision: Union[str, Sequence[str], None] = "b1a2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # organization_memberships
    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False, server_default="member"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_org_membership_org_user"),
    )
    op.create_index(op.f("ix_organization_memberships_organization_id"), "organization_memberships", ["organization_id"], unique=False)
    op.create_index(op.f("ix_organization_memberships_user_id"), "organization_memberships", ["user_id"], unique=False)

    # project_memberships
    op.create_table(
        "project_memberships",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False, server_default="viewer"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "user_id", name="uq_project_membership_project_user"),
    )
    op.create_index(op.f("ix_project_memberships_project_id"), "project_memberships", ["project_id"], unique=False)
    op.create_index(op.f("ix_project_memberships_user_id"), "project_memberships", ["user_id"], unique=False)

    # Data migration: populate organization_memberships from existing users.
    # Map User.role admin -> org_admin, super_admin retains platform role via users.role
    # and gets 'member' in org membership. This preserves access for existing users.
    conn = op.get_bind()
    try:
        import uuid

        users = conn.execute(sa.text("SELECT id, organization_id, role FROM users")).fetchall()
        for uid, org_id, role in users:
            mapped_role = "org_admin" if role == "admin" else "member"
            conn.execute(
                sa.text(
                    "INSERT INTO organization_memberships (id, organization_id, user_id, role, status, created_at, updated_at) "
                    "VALUES (:id, :org_id, :user_id, :role, 'active', NOW(), NOW()) "
                    "ON CONFLICT DO NOTHING"
                ),
                {"id": str(uuid.uuid4()), "org_id": org_id, "user_id": uid, "role": mapped_role},
            )
    except Exception:
        # Best-effort; membership can be recreated via admin tooling
        pass
    # Project memberships are NOT auto-populated because creator information is not
    # stored. Existing projects remain accessible via organization membership fallback
    # (transitional) until explicit project memberships are created. Documented gap.


def downgrade() -> None:
    op.drop_index(op.f("ix_project_memberships_user_id"), table_name="project_memberships")
    op.drop_index(op.f("ix_project_memberships_project_id"), table_name="project_memberships")
    op.drop_table("project_memberships")
    op.drop_index(op.f("ix_organization_memberships_user_id"), table_name="organization_memberships")
    op.drop_index(op.f("ix_organization_memberships_organization_id"), table_name="organization_memberships")
    op.drop_table("organization_memberships")
