"""enable RLS for external attack surface tables
Revision ID: e15b1c2d3e4f5
Revises: e15a1b2c3d4e
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
revision: str = "e15b1c2d3e4f5"
down_revision: Union[str, Sequence[str], None] = "e15a1b2c3d4e"
branch_labels = None
depends_on = None
def _org_or_empty():
    return "current_setting('app.current_organization_id', true) = '' OR current_setting('app.current_organization_id', true) IS NULL"
def _proj_or_empty():
    return "current_setting('app.current_project_id', true) = '' OR current_setting('app.current_project_id', true) IS NULL"
def upgrade():
    show_org = "current_setting('app.current_organization_id', true)"
    show_proj = "current_setting('app.current_project_id', true)"
    # external_scopes: org + project isolation (project enforced when set, org primary)
    op.execute(sa.text("ALTER TABLE external_scopes ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE external_scopes FORCE ROW LEVEL SECURITY"))
    condition_scopes = f"({show_org} = '' OR {show_org} IS NULL OR external_scopes.organization_id = {show_org}) AND ({show_proj} = '' OR {show_proj} IS NULL OR external_scopes.project_id = {show_proj})"
    op.execute(sa.text(f"CREATE POLICY tenant_isolation_external_scopes ON external_scopes FOR ALL USING ({condition_scopes}) WITH CHECK ({condition_scopes})"))
    # external_scope_entries: via parent scope (prevents FK bypass)
    op.execute(sa.text("ALTER TABLE external_scope_entries ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE external_scope_entries FORCE ROW LEVEL SECURITY"))
    condition_entries = f"EXISTS (SELECT 1 FROM external_scopes s WHERE s.id = external_scope_entries.external_scope_id AND ({show_org} = '' OR {show_org} IS NULL OR s.organization_id = {show_org}) AND ({show_proj} = '' OR {show_proj} IS NULL OR s.project_id = {show_proj}))"
    op.execute(sa.text(f"CREATE POLICY tenant_isolation_external_scope_entries ON external_scope_entries FOR ALL USING ({condition_entries}) WITH CHECK ({condition_entries})"))
    # external_discovery_runs: org + project isolation
    op.execute(sa.text("ALTER TABLE external_discovery_runs ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE external_discovery_runs FORCE ROW LEVEL SECURITY"))
    condition_runs = f"({show_org} = '' OR {show_org} IS NULL OR external_discovery_runs.organization_id = {show_org}) AND ({show_proj} = '' OR {show_proj} IS NULL OR external_discovery_runs.project_id = {show_proj})"
    op.execute(sa.text(f"CREATE POLICY tenant_isolation_external_discovery_runs ON external_discovery_runs FOR ALL USING ({condition_runs}) WITH CHECK ({condition_runs})"))
def downgrade():
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation_external_discovery_runs ON external_discovery_runs"))
    op.execute(sa.text("ALTER TABLE external_discovery_runs NO FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE external_discovery_runs DISABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation_external_scope_entries ON external_scope_entries"))
    op.execute(sa.text("ALTER TABLE external_scope_entries NO FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE external_scope_entries DISABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation_external_scopes ON external_scopes"))
    op.execute(sa.text("ALTER TABLE external_scopes NO FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE external_scopes DISABLE ROW LEVEL SECURITY"))
