"""add security validations e14

Revision ID: f14a2b3c4d5e
Revises: e13f6a7b8c9d
Create Date: 2026-09-12
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "f14a2b3c4d5e"
down_revision: Union[str, Sequence[str], None] = "e13f6a7b8c9d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_validations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.String(length=36), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requested_by", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="QUEUED"),
        sa.Column("validation_type", sa.String(length=30), nullable=False),
        sa.Column("scanner", sa.String(length=50), nullable=True),
        sa.Column("scanner_version", sa.String(length=50), nullable=True),
        sa.Column("scanner_digest", sa.String(length=128), nullable=True),
        sa.Column("target", sa.String(length=500), nullable=True),
        sa.Column("original_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("observed_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("verdict", sa.String(length=20), nullable=True),
        sa.Column("confidence", sa.String(length=20), nullable=True),
        sa.Column("evidence", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("error_code", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_security_validations_project_finding", "security_validations", ["project_id", "finding_id"])
    op.create_index("ix_security_validations_project_status", "security_validations", ["project_id", "status"])
    op.create_index("ix_security_validations_project_created", "security_validations", ["project_id", "created_at"])
    op.create_index("ix_security_validations_project_verdict", "security_validations", ["project_id", "verdict"])


def downgrade() -> None:
    op.drop_index("ix_security_validations_project_verdict", table_name="security_validations")
    op.drop_index("ix_security_validations_project_created", table_name="security_validations")
    op.drop_index("ix_security_validations_project_status", table_name="security_validations")
    op.drop_index("ix_security_validations_project_finding", table_name="security_validations")
    op.drop_table("security_validations")
