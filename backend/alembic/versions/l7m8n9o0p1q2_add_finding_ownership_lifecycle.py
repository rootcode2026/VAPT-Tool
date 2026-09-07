"""add finding ownership lifecycle

Revision ID: l7m8n9o0p1q2
Revises: k6l7m8n9o0p1
Create Date: 2026-09-20
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "l7m8n9o0p1q2"
down_revision: Union[str, Sequence[str], None] = "k6l7m8n9o0p1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add ownership tracking to findings
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("assigned_by", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("owner_team_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("workflow_status", sa.String(length=30), nullable=True))
        batch.add_column(sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("closed_by", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("remediation_claimed_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("remediation_claimed_by", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("ready_for_retest_at", sa.DateTime(timezone=True), nullable=True))

    # Extend finding_history for enterprise audit
    with op.batch_alter_table("finding_history") as batch:
        batch.add_column(sa.Column("organization_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("project_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("request_id", sa.String(length=100), nullable=True))
        batch.add_column(sa.Column("correlation_id", sa.String(length=100), nullable=True))
        batch.add_column(sa.Column("metadata", sa.JSON, nullable=True))

    # Indexes for new columns
    op.create_index("ix_findings_workflow_status", "findings", ["workflow_status"])
    op.create_index("ix_findings_assigned_at", "findings", ["assigned_at"])
    op.create_index("ix_finding_history_org", "finding_history", ["organization_id"])
    op.create_index("ix_finding_history_project", "finding_history", ["project_id"])

    # RLS for finding_history (project-scoped via finding -> project)
    try:
        op.execute(sa.text("ALTER TABLE finding_history ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text("ALTER TABLE finding_history FORCE ROW LEVEL SECURITY"))
        op.execute(sa.text("""
            CREATE POLICY tenant_isolation_finding_history ON finding_history
            FOR ALL
            USING (
                EXISTS (SELECT 1 FROM findings f JOIN targets t ON t.id = f.target_id JOIN projects p ON p.id = t.project_id WHERE f.id = finding_history.finding_id AND p.organization_id = current_setting('app.current_organization_id', true))
                OR current_setting('app.current_organization_id', true) = '' OR current_setting('app.current_organization_id', true) IS NULL
            )
            WITH CHECK (
                EXISTS (SELECT 1 FROM findings f JOIN targets t ON t.id = f.target_id JOIN projects p ON p.id = t.project_id WHERE f.id = finding_history.finding_id AND p.organization_id = current_setting('app.current_organization_id', true))
                OR current_setting('app.current_organization_id', true) = '' OR current_setting('app.current_organization_id', true) IS NULL
            )
        """))
    except Exception:
        pass


def downgrade() -> None:
    try:
        op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation_finding_history ON finding_history"))
        op.execute(sa.text("ALTER TABLE finding_history DISABLE ROW LEVEL SECURITY"))
    except Exception:
        pass
    op.drop_index("ix_finding_history_project", table_name="finding_history")
    op.drop_index("ix_finding_history_org", table_name="finding_history")
    op.drop_index("ix_findings_assigned_at", table_name="findings")
    op.drop_index("ix_findings_workflow_status", table_name="findings")
    with op.batch_alter_table("finding_history") as batch:
        batch.drop_column("metadata")
        batch.drop_column("correlation_id")
        batch.drop_column("request_id")
        batch.drop_column("project_id")
        batch.drop_column("organization_id")
    with op.batch_alter_table("findings") as batch:
        batch.drop_column("ready_for_retest_at")
        batch.drop_column("remediation_claimed_by")
        batch.drop_column("remediation_claimed_at")
        batch.drop_column("closed_by")
        batch.drop_column("closed_at")
        batch.drop_column("workflow_status")
        batch.drop_column("owner_team_id")
        batch.drop_column("assigned_by")
        batch.drop_column("assigned_at")
