"""add finding metadata and assets

Revision ID: b4e8c21a9d70
Revises: ead3c4176891
Create Date: 2026-09-02 22:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "b4e8c21a9d70"
down_revision: Union[str, Sequence[str], None] = "d7c4e91f2a08"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("first_seen_scan_id", sa.String(length=36), nullable=True),
        sa.Column("last_seen_scan_id", sa.String(length=36), nullable=True),
        sa.Column("asset_type", sa.String(length=50), nullable=False),
        sa.Column("value", sa.String(length=1024), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.ForeignKeyConstraint(["first_seen_scan_id"], ["scans.id"]),
        sa.ForeignKeyConstraint(["last_seen_scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id",
            "asset_type",
            "value",
            name="uq_assets_project_type_value",
        ),
    )
    op.create_index(
        op.f("ix_assets_project_id"),
        "assets",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_assets_first_seen_scan_id"),
        "assets",
        ["first_seen_scan_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_assets_last_seen_scan_id"),
        "assets",
        ["last_seen_scan_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_assets_asset_type"),
        "assets",
        ["asset_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_assets_value"),
        "assets",
        ["value"],
        unique=False,
    )

    op.add_column(
        "findings",
        sa.Column(
            "asset_id",
            sa.String(length=36),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_findings_asset_id",
        "findings",
        "assets",
        ["asset_id"],
        ["id"],
    )
    op.create_index(
        op.f("ix_findings_asset_id"),
        "findings",
        ["asset_id"],
        unique=False,
    )
    op.add_column(
        "findings",
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("findings", "metadata")
    op.drop_index(op.f("ix_findings_asset_id"), table_name="findings")
    op.drop_constraint("fk_findings_asset_id", "findings", type_="foreignkey")
    op.drop_column("findings", "asset_id")

    op.drop_index(op.f("ix_assets_value"), table_name="assets")
    op.drop_index(op.f("ix_assets_asset_type"), table_name="assets")
    op.drop_index(op.f("ix_assets_last_seen_scan_id"), table_name="assets")
    op.drop_index(op.f("ix_assets_first_seen_scan_id"), table_name="assets")
    op.drop_index(op.f("ix_assets_project_id"), table_name="assets")
    op.drop_table("assets")
