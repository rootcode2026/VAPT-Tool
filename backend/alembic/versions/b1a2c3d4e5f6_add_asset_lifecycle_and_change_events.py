"""add asset lifecycle and change events

Revision ID: b1a2c3d4e5f6
Revises: c9b2f4a7e1d3
Create Date: 2026-09-03 17:25:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "b1a2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "c9b2f4a7e1d3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="active",
        ),
    )
    op.create_index(
        "ix_assets_status",
        "assets",
        ["status"],
        unique=False,
    )

    op.create_table(
        "asset_change_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("change_type", sa.String(length=50), nullable=False),
        sa.Column(
            "previous_state",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "current_state",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_id",
            "asset_id",
            "change_type",
            name="uq_asset_change_events_idempotency",
        ),
    )
    op.create_index(
        "ix_asset_change_events_project_id",
        "asset_change_events",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_asset_change_events_asset_id",
        "asset_change_events",
        ["asset_id"],
        unique=False,
    )
    op.create_index(
        "ix_asset_change_events_scan_id",
        "asset_change_events",
        ["scan_id"],
        unique=False,
    )
    op.create_index(
        "ix_asset_change_events_change_type",
        "asset_change_events",
        ["change_type"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_asset_change_events_change_type", table_name="asset_change_events")
    op.drop_index("ix_asset_change_events_scan_id", table_name="asset_change_events")
    op.drop_index("ix_asset_change_events_asset_id", table_name="asset_change_events")
    op.drop_index("ix_asset_change_events_project_id", table_name="asset_change_events")
    op.drop_table("asset_change_events")

    op.drop_index("ix_assets_status", table_name="assets")
    op.drop_column("assets", "status")
