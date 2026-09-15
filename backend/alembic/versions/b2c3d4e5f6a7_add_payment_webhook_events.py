"""add payment webhook events for durable idempotency
Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-09-15
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
        "payment_webhook_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False, server_default=sa.text("'mock'")),
        sa.Column("provider_event_id", sa.String(length=100), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=True),
        sa.Column("event_type", sa.String(length=50), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider", "provider_event_id", name="uq_webhook_provider_event"),
    )
    op.create_index("ix_webhook_provider_event", "payment_webhook_events", ["provider", "provider_event_id"])
    op.create_index("ix_webhook_org", "payment_webhook_events", ["organization_id"])
    op.execute(sa.text("ALTER TABLE payment_webhook_events ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE payment_webhook_events FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("""
        CREATE POLICY tenant_isolation_payment_webhook_events ON payment_webhook_events FOR ALL
        USING (organization_id IS NULL OR organization_id = current_setting('app.current_organization_id', true) OR current_setting('app.current_organization_id', true) = '' OR current_setting('app.current_organization_id', true) IS NULL)
        WITH CHECK (organization_id IS NULL OR organization_id = current_setting('app.current_organization_id', true) OR current_setting('app.current_organization_id', true) = '' OR current_setting('app.current_organization_id', true) IS NULL)
    """))

def downgrade() -> None:
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation_payment_webhook_events ON payment_webhook_events"))
    op.execute(sa.text("ALTER TABLE payment_webhook_events DISABLE ROW LEVEL SECURITY"))
    op.drop_table("payment_webhook_events")
