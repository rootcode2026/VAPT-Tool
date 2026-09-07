"""enable RLS for tenant tables

Revision ID: i9a0b1c2d3e4
Revises: h8a9b0c1d2e3
Create Date: 2026-09-15
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "i9a0b1c2d3e4"
down_revision: Union[str, Sequence[str], None] = "h8a9b0c1d2e3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Tables to enable RLS — high-value tenant-scoped
TABLES = ["projects", "targets", "scans", "findings", "assets", "reports", "ai_conversations", "repository_connections", "cloud_connections"]

# Column scoping for each table, based on the real schema:
#   org_direct   -> table has organization_id directly
#   project_direct -> table has project_id directly (join to projects for org)
#   via_target   -> table has target_id only (join targets -> projects for org)
TABLE_SCOPING = {
    "projects": "org_direct",            # has organization_id
    "reports": "org_direct",             # has organization_id
    "ai_conversations": "org_direct",    # has organization_id
    "assets": "project_direct",          # has project_id
    "targets": "project_direct",         # has project_id
    "cloud_connections": "project_direct",  # has project_id (no organization_id)
    "repository_connections": "project_direct",  # has project_id (no organization_id)
    "scans": "via_target",               # has target_id only
    "findings": "via_target",            # has target_id only
}

def _org_or_empty() -> str:
    return (
        "current_setting('app.current_organization_id', true) = '' "
        "OR current_setting('app.current_organization_id', true) IS NULL"
    )

def upgrade() -> None:
    # Enable RLS and create permissive tenant policies
    # Policies use current_setting('app.current_organization_id', true)
    # When no tenant is set (empty), allow superuser/bypass (for migrations, system tasks)
    show = "current_setting('app.current_organization_id', true)"
    for table in TABLES:
        op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        # Force RLS for table owner as well
        op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        # Policy: allow if the row belongs to the current organization or the tenant
        # setting is unset (system/migration). Scoping differs by table schema.
        scope = TABLE_SCOPING.get(table, "org_direct")
        if scope == "org_direct":
            condition = (
                f"{table}.organization_id = {show} "
                f"OR {_org_or_empty()}"
            )
        elif scope == "project_direct":
            condition = (
                f"EXISTS (SELECT 1 FROM projects p "
                f"WHERE p.id = {table}.project_id AND (p.organization_id = {show} OR {_org_or_empty()})) "
                f"OR {_org_or_empty()}"
            )
        elif scope == "via_target":
            condition = (
                f"EXISTS (SELECT 1 FROM targets rt JOIN projects p ON p.id = rt.project_id "
                f"WHERE rt.id = {table}.target_id AND (p.organization_id = {show} OR {_org_or_empty()})) "
                f"OR {_org_or_empty()}"
            )
        else:
            condition = "true"
        op.execute(sa.text(f"""
            CREATE POLICY tenant_isolation_{table} ON {table}
            FOR ALL
            USING ({condition})
            WITH CHECK ({condition})
        """))

def downgrade() -> None:
    for table in TABLES:
        op.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation_{table} ON {table}"))
        op.execute(sa.text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))
