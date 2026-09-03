"""add scanner execution observability

Revision ID: c9b2f4a7e1d3
Revises: f8c3a1d4e2b0
Create Date: 2026-09-03 16:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c9b2f4a7e1d3"
down_revision: Union[str, Sequence[str], None] = "f8c3a1d4e2b0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "progress",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    op.add_column(
        "scan_results",
        sa.Column("duration_ms", sa.Integer(), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column(
            "attempt",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "scan_results",
        sa.Column(
            "max_attempts",
            sa.Integer(),
            nullable=False,
            server_default="2",
        ),
    )
    op.add_column(
        "scan_results",
        sa.Column("error_type", sa.String(length=50), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column("error_phase", sa.String(length=50), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column("retryable", sa.Boolean(), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column("findings_count", sa.Integer(), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column("assets_count", sa.Integer(), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )

    op.alter_column(
        "scan_results",
        "started_at",
        existing_type=sa.DateTime(),
        type_=sa.DateTime(timezone=True),
        existing_nullable=True,
        postgresql_using="started_at AT TIME ZONE 'UTC'",
    )
    op.alter_column(
        "scan_results",
        "completed_at",
        existing_type=sa.DateTime(),
        type_=sa.DateTime(timezone=True),
        existing_nullable=True,
        postgresql_using="completed_at AT TIME ZONE 'UTC'",
    )

    op.create_index(
        "ix_scan_results_status",
        "scan_results",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_scan_results_scan_id_scanner",
        "scan_results",
        ["scan_id", "scanner"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_scan_results_scan_id_scanner", table_name="scan_results")
    op.drop_index("ix_scan_results_status", table_name="scan_results")

    op.alter_column(
        "scan_results",
        "completed_at",
        existing_type=sa.DateTime(timezone=True),
        type_=sa.DateTime(),
        existing_nullable=True,
        postgresql_using="completed_at",
    )
    op.alter_column(
        "scan_results",
        "started_at",
        existing_type=sa.DateTime(timezone=True),
        type_=sa.DateTime(),
        existing_nullable=True,
        postgresql_using="started_at",
    )

    op.drop_column("scan_results", "metadata")
    op.drop_column("scan_results", "assets_count")
    op.drop_column("scan_results", "findings_count")
    op.drop_column("scan_results", "retryable")
    op.drop_column("scan_results", "error_phase")
    op.drop_column("scan_results", "error_message")
    op.drop_column("scan_results", "error_type")
    op.drop_column("scan_results", "max_attempts")
    op.drop_column("scan_results", "attempt")
    op.drop_column("scan_results", "duration_ms")
    op.drop_column("scans", "progress")
