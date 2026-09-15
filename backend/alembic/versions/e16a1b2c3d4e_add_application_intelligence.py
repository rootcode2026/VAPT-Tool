"""add application intelligence e16

Revision ID: e16a1b2c3d4e
Revises: e15b1c2d3e4f5
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
revision: str = "e16a1b2c3d4e"
down_revision: Union[str, Sequence[str], None] = "e15b1c2d3e4f5"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "applications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("application_type", sa.String(30), nullable=False, server_default="UNKNOWN"),
        sa.Column("lifecycle", sa.String(20), nullable=False, server_default="UNKNOWN"),
        sa.Column("criticality", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("owner_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("owner_team_id", sa.String(36), nullable=True),
        sa.Column("repository_asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("primary_domain", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("metadata", sa.JSON, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("project_id", "name", name="uq_applications_project_name"),
    )
    op.create_index("ix_applications_project", "applications", ["project_id"])
    op.create_index("ix_applications_org", "applications", ["organization_id"])
    op.create_index("ix_applications_status", "applications", ["status"])
    op.create_index("ix_applications_lifecycle", "applications", ["lifecycle"])
    op.create_index("ix_applications_criticality", "applications", ["criticality"])
    op.create_index("ix_applications_owner", "applications", ["owner_user_id"])

    op.create_table(
        "application_assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship_type", sa.String(30), nullable=False, server_default="contains"),
        sa.Column("confidence", sa.String(20), nullable=False, server_default="MEDIUM"),
        sa.Column("evidence", sa.JSON, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("application_id", "asset_id", name="uq_app_asset"),
    )
    op.create_index("ix_app_assets_app", "application_assets", ["application_id"])
    op.create_index("ix_app_assets_asset", "application_assets", ["asset_id"])

    # RLS
    show_org = "current_setting('app.current_organization_id', true)"
    show_proj = "current_setting('app.current_project_id', true)"
    op.execute(sa.text("ALTER TABLE applications ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE applications FORCE ROW LEVEL SECURITY"))
    cond_app = f"({show_org} = '' OR {show_org} IS NULL OR applications.organization_id = {show_org}) AND ({show_proj} = '' OR {show_proj} IS NULL OR applications.project_id = {show_proj})"
    op.execute(sa.text(f"CREATE POLICY tenant_isolation_applications ON applications FOR ALL USING ({cond_app}) WITH CHECK ({cond_app})"))

    op.execute(sa.text("ALTER TABLE application_assets ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE application_assets FORCE ROW LEVEL SECURITY"))
    cond_assets = f"EXISTS (SELECT 1 FROM applications a WHERE a.id = application_assets.application_id AND ({show_org} = '' OR {show_org} IS NULL OR a.organization_id = {show_org}) AND ({show_proj} = '' OR {show_proj} IS NULL OR a.project_id = {show_proj}))"
    op.execute(sa.text(f"CREATE POLICY tenant_isolation_application_assets ON application_assets FOR ALL USING ({cond_assets}) WITH CHECK ({cond_assets})"))

def downgrade():
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation_application_assets ON application_assets"))
    op.execute(sa.text("ALTER TABLE application_assets NO FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE application_assets DISABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation_applications ON applications"))
    op.execute(sa.text("ALTER TABLE applications NO FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE applications DISABLE ROW LEVEL SECURITY"))
    op.drop_index("ix_app_assets_asset", table_name="application_assets")
    op.drop_index("ix_app_assets_app", table_name="application_assets")
    op.drop_table("application_assets")
    op.drop_index("ix_applications_owner", table_name="applications")
    op.drop_index("ix_applications_criticality", table_name="applications")
    op.drop_index("ix_applications_lifecycle", table_name="applications")
    op.drop_index("ix_applications_status", table_name="applications")
    op.drop_index("ix_applications_org", table_name="applications")
    op.drop_index("ix_applications_project", table_name="applications")
    op.drop_table("applications")
