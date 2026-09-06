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

def upgrade() -> None:
    # Enable RLS and create permissive tenant policies
    # Policies use current_setting('app.current_organization_id', true)
    # When no tenant is set (empty), allow superuser/bypass (for migrations, system tasks)
    for table in TABLES:
        op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        # Force RLS for table owner as well
        op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        # Policy: allow if organization_id matches current_setting or if setting is empty (system)
        # For tables that use project_id -> need to join, but for simplicity check organization_id directly where available
        # For projects, direct check; for others via project join, we use a function-based policy via subquery
        if table in ("projects", "reports", "ai_conversations", "repository_connections", "cloud_connections"):
            # These have organization_id directly
            op.execute(sa.text(f"""
                CREATE POLICY tenant_isolation_{table} ON {table}
                FOR ALL
                USING (
                    organization_id = current_setting('app.current_organization_id', true)
                    OR current_setting('app.current_organization_id', true) = ''
                    OR current_setting('app.current_organization_id', true) IS NULL
                )
                WITH CHECK (
                    organization_id = current_setting('app.current_organization_id', true)
                    OR current_setting('app.current_organization_id', true) = ''
                    OR current_setting('app.current_organization_id', true) IS NULL
                )
            """))
        elif table in ("targets", "scans"):
            # These have project_id -> need to check via projects
            op.execute(sa.text(f"""
                CREATE POLICY tenant_isolation_{table} ON {table}
                FOR ALL
                USING (
                    EXISTS (
                        SELECT 1 FROM projects p
                        WHERE p.id = {table}.project_id
                        AND (p.organization_id = current_setting('app.current_organization_id', true)
                             OR current_setting('app.current_organization_id', true) = ''
                             OR current_setting('app.current_organization_id', true) IS NULL)
                    )
                    OR current_setting('app.current_organization_id', true) = ''
                    OR current_setting('app.current_organization_id', true) IS NULL
                )
                WITH CHECK (
                    EXISTS (
                        SELECT 1 FROM projects p
                        WHERE p.id = {table}.project_id
                        AND (p.organization_id = current_setting('app.current_organization_id', true)
                             OR current_setting('app.current_organization_id', true) = ''
                             OR current_setting('app.current_organization_id', true) IS NULL)
                    )
                    OR current_setting('app.current_organization_id', true) = ''
                    OR current_setting('app.current_organization_id', true) IS NULL
                )
            """))
        elif table in ("findings", "assets"):
            # findings/assets have project_id directly or via target
            op.execute(sa.text(f"""
                CREATE POLICY tenant_isolation_{table} ON {table}
                FOR ALL
                USING (
                    project_id = current_setting('app.current_project_id', true)
                    OR EXISTS (
                        SELECT 1 FROM projects p WHERE p.id = {table}.project_id
                        AND p.organization_id = current_setting('app.current_organization_id', true)
                    )
                    OR current_setting('app.current_organization_id', true) = ''
                    OR current_setting('app.current_organization_id', true) IS NULL
                )
                WITH CHECK (
                    project_id = current_setting('app.current_project_id', true)
                    OR EXISTS (
                        SELECT 1 FROM projects p WHERE p.id = {table}.project_id
                        AND p.organization_id = current_setting('app.current_organization_id', true)
                    )
                    OR current_setting('app.current_organization_id', true) = ''
                    OR current_setting('app.current_organization_id', true) IS NULL
                )
            """))
        else:
            op.execute(sa.text(f"""
                CREATE POLICY tenant_isolation_{table} ON {table}
                FOR ALL
                USING (true)
                WITH CHECK (true)
            """))

def downgrade() -> None:
    for table in TABLES:
        op.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation_{table} ON {table}"))
        op.execute(sa.text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))
