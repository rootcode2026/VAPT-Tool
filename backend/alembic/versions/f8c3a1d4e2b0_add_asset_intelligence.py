"""add asset observation timestamps and relationships

Revision ID: f8c3a1d4e2b0
Revises: b4e8c21a9d70
Create Date: 2026-09-03 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "f8c3a1d4e2b0"
down_revision: Union[str, Sequence[str], None] = "b4e8c21a9d70"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        op.f("ix_assets_first_seen_at"),
        "assets",
        ["first_seen_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_assets_last_seen_at"),
        "assets",
        ["last_seen_at"],
        unique=False,
    )
    op.execute(
        """
        UPDATE assets
        SET
            first_seen_at = COALESCE(first_seen_at, created_at),
            last_seen_at = COALESCE(last_seen_at, updated_at, created_at)
        """
    )

    op.create_table(
        "asset_relationships",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("source_asset_id", sa.String(length=36), nullable=False),
        sa.Column("target_asset_id", sa.String(length=36), nullable=False),
        sa.Column("relationship_type", sa.String(length=50), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.ForeignKeyConstraint(["source_asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["target_asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            name="uq_asset_relationships_identity",
        ),
    )
    op.create_index(
        op.f("ix_asset_relationships_project_id"),
        "asset_relationships",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_asset_relationships_source_asset_id"),
        "asset_relationships",
        ["source_asset_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_asset_relationships_target_asset_id"),
        "asset_relationships",
        ["target_asset_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_asset_relationships_relationship_type"),
        "asset_relationships",
        ["relationship_type"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_asset_relationships_relationship_type"),
        table_name="asset_relationships",
    )
    op.drop_index(
        op.f("ix_asset_relationships_target_asset_id"),
        table_name="asset_relationships",
    )
    op.drop_index(
        op.f("ix_asset_relationships_source_asset_id"),
        table_name="asset_relationships",
    )
    op.drop_index(
        op.f("ix_asset_relationships_project_id"),
        table_name="asset_relationships",
    )
    op.drop_table("asset_relationships")
    op.drop_index(op.f("ix_assets_last_seen_at"), table_name="assets")
    op.drop_index(op.f("ix_assets_first_seen_at"), table_name="assets")
    op.drop_column("assets", "last_seen_at")
    op.drop_column("assets", "first_seen_at")
