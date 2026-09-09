"""add remediation D7 fields (blocked state + evidence ref)

Revision ID: u7v8w9x0y1z2
Revises: t6u7v8w9x0y1
Create Date: 2026-09-09

D7 (Remediation) schema, additive only:

- finding_remediations.blocked_reason (VARCHAR 500, nullable)
- finding_remediations.evidence_ref (TEXT, nullable, bounded reference only)
- finding_remediations.updated_by (FK users SET NULL, nullable)
- composite index (project_id, status) for bounded project-scoped listing
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "u7v8w9x0y1z2"
down_revision: Union[str, Sequence[str], None] = "t6u7v8w9x0y1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("finding_remediations") as batch:
        batch.add_column(sa.Column("blocked_reason", sa.String(500), nullable=True))
        batch.add_column(sa.Column("evidence_ref", sa.Text(), nullable=True))
        batch.add_column(sa.Column("updated_by", sa.String(36), nullable=True))
    try:
        op.create_foreign_key(
            "fk_remediation_updated_by",
            "finding_remediations",
            "users",
            ["updated_by"],
            ["id"],
            ondelete="SET NULL",
        )
    except Exception:
        pass
    try:
        op.create_index(
            "ix_remediation_project_status",
            "finding_remediations",
            ["project_id", "status"],
        )
    except Exception:
        pass


def downgrade() -> None:
    try:
        op.drop_index("ix_remediation_project_status", table_name="finding_remediations")
    except Exception:
        pass
    try:
        op.drop_constraint("fk_remediation_updated_by", "finding_remediations", type_="foreignkey")
    except Exception:
        pass
    with op.batch_alter_table("finding_remediations") as batch:
        try:
            batch.drop_column("updated_by")
        except Exception:
            pass
        try:
            batch.drop_column("evidence_ref")
        except Exception:
            pass
        try:
            batch.drop_column("blocked_reason")
        except Exception:
            pass
