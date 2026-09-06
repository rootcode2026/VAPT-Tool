"""add finding SLA remediation retest tables

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-09-09
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, Sequence[str], None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sla_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("target_hours", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "severity", name="uq_sla_policies_org_severity"),
    )
    op.create_index("ix_sla_policies_org", "sla_policies", ["organization_id"], unique=False)

    op.create_table(
        "finding_slas",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("policy_name", sa.String(length=100), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("target_hours", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("due_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("breached_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_slas_finding", "finding_slas", ["finding_id"], unique=False)
    op.create_index("ix_finding_slas_org", "finding_slas", ["organization_id"], unique=False)
    op.create_index("ix_finding_slas_project", "finding_slas", ["project_id"], unique=False)
    op.create_index("ix_finding_slas_status", "finding_slas", ["status"], unique=False)
    op.create_index("ix_finding_slas_due", "finding_slas", ["due_at"], unique=False)

    op.create_table(
        "finding_risk_acceptances",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("requested_by", sa.String(length=36), nullable=True),
        sa.Column("approved_by", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="requested"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("business_justification", sa.Text(), nullable=True),
        sa.Column("compensating_controls", sa.Text(), nullable=True),
        sa.Column("valid_from", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_fra_finding", "finding_risk_acceptances", ["finding_id"], unique=False)
    op.create_index("ix_fra_org", "finding_risk_acceptances", ["organization_id"], unique=False)
    op.create_index("ix_fra_project", "finding_risk_acceptances", ["project_id"], unique=False)
    op.create_index("ix_fra_status", "finding_risk_acceptances", ["status"], unique=False)
    op.create_index("ix_fra_expires", "finding_risk_acceptances", ["expires_at"], unique=False)

    op.create_table(
        "finding_remediations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("created_by", sa.String(length=36), nullable=True),
        sa.Column("assigned_to", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="open"),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("remediation_guidance", sa.Text(), nullable=True),
        sa.Column("due_at", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("completion_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_frem_finding", "finding_remediations", ["finding_id"], unique=False)
    op.create_index("ix_frem_org", "finding_remediations", ["organization_id"], unique=False)
    op.create_index("ix_frem_project", "finding_remediations", ["project_id"], unique=False)
    op.create_index("ix_frem_status", "finding_remediations", ["status"], unique=False)
    op.create_index("ix_frem_assigned", "finding_remediations", ["assigned_to"], unique=False)

    op.create_table(
        "finding_retests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("requested_by", sa.String(length=36), nullable=True),
        sa.Column("executed_by", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="requested"),
        sa.Column("scanner", sa.String(length=50), nullable=True),
        sa.Column("target_value", sa.String(length=255), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("result", sa.String(length=20), nullable=True),
        sa.Column("result_summary", sa.Text(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["executed_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_fret_finding", "finding_retests", ["finding_id"], unique=False)
    op.create_index("ix_fret_org", "finding_retests", ["organization_id"], unique=False)
    op.create_index("ix_fret_project", "finding_retests", ["project_id"], unique=False)
    op.create_index("ix_fret_status", "finding_retests", ["status"], unique=False)
    op.create_index("ix_fret_created", "finding_retests", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_fret_created", table_name="finding_retests")
    op.drop_index("ix_fret_status", table_name="finding_retests")
    op.drop_index("ix_fret_project", table_name="finding_retests")
    op.drop_index("ix_fret_org", table_name="finding_retests")
    op.drop_index("ix_fret_finding", table_name="finding_retests")
    op.drop_table("finding_retests")
    op.drop_index("ix_frem_assigned", table_name="finding_remediations")
    op.drop_index("ix_frem_status", table_name="finding_remediations")
    op.drop_index("ix_frem_project", table_name="finding_remediations")
    op.drop_index("ix_frem_org", table_name="finding_remediations")
    op.drop_index("ix_frem_finding", table_name="finding_remediations")
    op.drop_table("finding_remediations")
    op.drop_index("ix_fra_expires", table_name="finding_risk_acceptances")
    op.drop_index("ix_fra_status", table_name="finding_risk_acceptances")
    op.drop_index("ix_fra_project", table_name="finding_risk_acceptances")
    op.drop_index("ix_fra_org", table_name="finding_risk_acceptances")
    op.drop_index("ix_fra_finding", table_name="finding_risk_acceptances")
    op.drop_table("finding_risk_acceptances")
    op.drop_index("ix_finding_slas_due", table_name="finding_slas")
    op.drop_index("ix_finding_slas_status", table_name="finding_slas")
    op.drop_index("ix_finding_slas_project", table_name="finding_slas")
    op.drop_index("ix_finding_slas_org", table_name="finding_slas")
    op.drop_index("ix_finding_slas_finding", table_name="finding_slas")
    op.drop_table("finding_slas")
    op.drop_index("ix_sla_policies_org", table_name="sla_policies")
    op.drop_table("sla_policies")
