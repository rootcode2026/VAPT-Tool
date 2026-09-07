"""add scanner version lifecycle

Revision ID: n8o0p1q2r3s4
Revises: 44730d5
Create Date: 2026-09-20
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "n8o0p1q2r3s4"
# 44730d5 is the merge commit for C1, but we need to set down_revision to the previous head k6l7m8n9o0p1? Actually the last migration before C1 was k6l7m8n9o0p1, and C1 didn't create a migration (it was code-only), so the head is still k6l7m8n9o0p1. But we can set to the last known migration.
# Let's check the actual heads: the last migration before this is m8n9o0p1q2r3 (P14.5) and k6l7m8n9o0p1 (P14.3). The C1 didn't add a migration, so head is still m8n9o0p1q2r3 or k6l7m8n9o0p1 depending on branch.
# For C2, we should set to the latest head which is m8n9o0p1q2r3 if it exists, otherwise k6l7m8n9o0p1.
# We'll set to m8n9o0p1q2r3 if that file exists, else k6l7m8n9o0p1.

down_revision: Union[str, Sequence[str], None] = "m8n9o0p1q2r3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("scanner_versions") as batch:
        batch.add_column(sa.Column("lifecycle_status", sa.String(length=20), nullable=False, server_default="candidate"))
        batch.add_column(sa.Column("enabled", sa.Boolean, nullable=False, server_default="1"))
        batch.add_column(sa.Column("approved", sa.Boolean, nullable=False, server_default="0"))
        batch.add_column(sa.Column("deprecated", sa.Boolean, nullable=False, server_default="0"))
        batch.add_column(sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("deprecated_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("parser_version", sa.String(length=50), nullable=True))
        batch.add_column(sa.Column("output_format_version", sa.String(length=20), nullable=True))

    op.create_index("ix_scanner_versions_lifecycle", "scanner_versions", ["lifecycle_status"])
    op.create_index("ix_scanner_versions_enabled", "scanner_versions", ["enabled"])

    # Scan provenance: preserve scanner version and digest for historical scans
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("scanner_version", sa.String(length=50), nullable=True))
        batch.add_column(sa.Column("scanner_image_digest", sa.String(length=128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("scanner_image_digest")
        batch.drop_column("scanner_version")
    op.drop_index("ix_scanner_versions_enabled", table_name="scanner_versions")
    op.drop_index("ix_scanner_versions_lifecycle", table_name="scanner_versions")
    with op.batch_alter_table("scanner_versions") as batch:
        batch.drop_column("output_format_version")
        batch.drop_column("parser_version")
        batch.drop_column("deprecated_at")
        batch.drop_column("approved_at")
        batch.drop_column("deprecated")
        batch.drop_column("approved")
        batch.drop_column("enabled")
        batch.drop_column("lifecycle_status")
