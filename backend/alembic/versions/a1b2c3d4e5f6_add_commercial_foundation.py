"""add commercial foundation — plans, subscriptions, licenses, usage_events, RLS
Revision ID: a1b2c3d4e5f6
Revises: z2a3b4c5d6e7
Create Date: 2026-09-15
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "z2a3b4c5d6e7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # plans — global, no RLS (shared catalog), but we keep it simple
    op.create_table(
        "plans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("code", sa.String(length=50), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("monthly_price", sa.Numeric(precision=12, scale=2), nullable=True),
        sa.Column("annual_price", sa.Numeric(precision=12, scale=2), nullable=True),
        sa.Column("currency", sa.String(length=10), nullable=False, server_default=sa.text("'INR'")),
        sa.Column("asset_limit", sa.Integer(), nullable=True),
        sa.Column("user_limit", sa.Integer(), nullable=True),
        sa.Column("project_limit", sa.Integer(), nullable=True),
        sa.Column("scan_limit", sa.Integer(), nullable=True),
        sa.Column("entitlements", sa.JSON(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("limits", sa.JSON(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code", name="uq_plans_code"),
    )
    op.create_index("ix_plans_active", "plans", ["active"])
    # seed default plans
    op.execute(sa.text("""
        INSERT INTO plans (id, code, name, description, active, monthly_price, annual_price, currency, asset_limit, user_limit, project_limit, scan_limit, entitlements, limits, metadata)
        VALUES
        ('00000000-0000-0000-0000-000000000001', 'free', 'Free / Community', 'Community / self-service', true, 0, 0, 'INR', 100, 5, 2, 50, '{"scanning.enabled": true, "monitoring.enabled": false, "attack_surface.enabled": false, "cloud_security.enabled": false, "application_security.enabled": false, "reporting.enabled": true, "pdf_reporting.enabled": false}'::jsonb, '{"assets": 100, "users": 5, "projects": 2}'::jsonb, '{}'::jsonb),
        ('00000000-0000-0000-0000-000000000002', 'starter', 'Starter', 'Starter plan', true, 9999, 99000, 'INR', 100, 10, 5, 200, '{"scanning.enabled": true, "monitoring.enabled": true, "attack_surface.enabled": true, "cloud_security.enabled": false, "application_security.enabled": true, "reporting.enabled": true, "pdf_reporting.enabled": true}'::jsonb, '{"assets": 100, "users": 10, "projects": 5}'::jsonb, '{}'::jsonb),
        ('00000000-0000-0000-0000-000000000003', 'growth', 'Growth', 'Growth plan', true, 29999, 299000, 'INR', 500, 25, 10, 1000, '{"scanning.enabled": true, "monitoring.enabled": true, "attack_surface.enabled": true, "cloud_security.enabled": true, "application_security.enabled": true, "reporting.enabled": true, "pdf_reporting.enabled": true, "advanced_analytics.enabled": true}'::jsonb, '{"assets": 500, "users": 25, "projects": 10}'::jsonb, '{}'::jsonb),
        ('00000000-0000-0000-0000-000000000004', 'business', 'Business', 'Business plan', true, 74999, 749000, 'INR', 2000, 100, 50, 5000, '{"scanning.enabled": true, "monitoring.enabled": true, "attack_surface.enabled": true, "cloud_security.enabled": true, "application_security.enabled": true, "reporting.enabled": true, "pdf_reporting.enabled": true, "advanced_analytics.enabled": true, "security_investigation.enabled": true}'::jsonb, '{"assets": 2000, "users": 100, "projects": 50}'::jsonb, '{}'::jsonb),
        ('00000000-0000-0000-0000-000000000005', 'enterprise', 'Enterprise', 'Custom enterprise', true, NULL, NULL, 'INR', NULL, NULL, NULL, NULL, '{"scanning.enabled": true, "monitoring.enabled": true, "attack_surface.enabled": true, "cloud_security.enabled": true, "application_security.enabled": true, "reporting.enabled": true, "pdf_reporting.enabled": true, "advanced_analytics.enabled": true, "security_investigation.enabled": true, "api_access.enabled": true}'::jsonb, '{}'::jsonb, '{"custom": true}'::jsonb)
    """))
    # subscriptions — tenant-scoped, RLS
    op.create_table(
        "subscriptions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("plan_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'active'")),
        sa.Column("billing_interval", sa.String(length=20), nullable=False, server_default=sa.text("'monthly'")),
        sa.Column("start_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("renewal_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancellation_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider", sa.String(length=50), nullable=False, server_default=sa.text("'mock'")),
        sa.Column("provider_customer_id", sa.String(length=100), nullable=True),
        sa.Column("provider_subscription_id", sa.String(length=100), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["plan_id"], ["plans.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_subscriptions_org", "subscriptions", ["organization_id"])
    op.create_index("ix_subscriptions_status", "subscriptions", ["status"])
    op.execute(sa.text("ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE subscriptions FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("""
        CREATE POLICY tenant_isolation_subscriptions ON subscriptions FOR ALL
        USING (organization_id = current_setting('app.current_organization_id', true) OR current_setting('app.current_organization_id', true) = '' OR current_setting('app.current_organization_id', true) IS NULL)
        WITH CHECK (organization_id = current_setting('app.current_organization_id', true) OR current_setting('app.current_organization_id', true) = '' OR current_setting('app.current_organization_id', true) IS NULL)
    """))
    # licenses — tenant-scoped, RLS
    op.create_table(
        "licenses",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("plan_id", sa.String(length=36), nullable=False),
        sa.Column("subscription_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'active'")),
        sa.Column("edition", sa.String(length=50), nullable=False, server_default=sa.text("'standard'")),
        sa.Column("entitlement_snapshot", sa.JSON(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("limits_snapshot", sa.JSON(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("issued_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("issuer_version", sa.String(length=50), nullable=False, server_default=sa.text("'v1'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["plan_id"], ["plans.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscriptions.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_licenses_org", "licenses", ["organization_id"])
    op.create_index("ix_licenses_status", "licenses", ["status"])
    op.execute(sa.text("ALTER TABLE licenses ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE licenses FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("""
        CREATE POLICY tenant_isolation_licenses ON licenses FOR ALL
        USING (organization_id = current_setting('app.current_organization_id', true) OR current_setting('app.current_organization_id', true) = '' OR current_setting('app.current_organization_id', true) IS NULL)
        WITH CHECK (organization_id = current_setting('app.current_organization_id', true) OR current_setting('app.current_organization_id', true) = '' OR current_setting('app.current_organization_id', true) IS NULL)
    """))
    # usage_events — tenant-scoped, RLS, idempotency
    op.create_table(
        "usage_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("event_key", sa.String(length=100), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "event_key", name="uq_usage_org_event_key"),
    )
    op.create_index("ix_usage_org_type", "usage_events", ["organization_id", "event_type"])
    op.execute(sa.text("ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE usage_events FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("""
        CREATE POLICY tenant_isolation_usage_events ON usage_events FOR ALL
        USING (organization_id = current_setting('app.current_organization_id', true) OR current_setting('app.current_organization_id', true) = '' OR current_setting('app.current_organization_id', true) IS NULL)
        WITH CHECK (organization_id = current_setting('app.current_organization_id', true) OR current_setting('app.current_organization_id', true) = '' OR current_setting('app.current_organization_id', true) IS NULL)
    """))

def downgrade() -> None:
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation_usage_events ON usage_events"))
    op.execute(sa.text("ALTER TABLE usage_events DISABLE ROW LEVEL SECURITY"))
    op.drop_table("usage_events")
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation_licenses ON licenses"))
    op.execute(sa.text("ALTER TABLE licenses DISABLE ROW LEVEL SECURITY"))
    op.drop_table("licenses")
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation_subscriptions ON subscriptions"))
    op.execute(sa.text("ALTER TABLE subscriptions DISABLE ROW LEVEL SECURITY"))
    op.drop_table("subscriptions")
    op.drop_table("plans")
