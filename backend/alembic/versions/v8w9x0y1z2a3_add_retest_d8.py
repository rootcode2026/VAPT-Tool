"""add retest verification D8 provenance + fingerprint columns

Revision ID: v8w9x0y1z2a3
Revises: u7v8w9x0y1z2
Create Date: 2026-09-09

D8 (Retesting & Verification) schema, additive only:

- finding_retests.scan_id (FK scans SET NULL, nullable, index)
- finding_retests.scanner_version / image_ref / image_digest / channel
- finding_retests.baseline_fingerprint / resulting_fingerprint / fingerprint_algo
- finding_retests.verification_note
- indexes (project_id, status), (finding_id, status)
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "v8w9x0y1z2a3"
down_revision: Union[str, Sequence[str], None] = "u7v8w9x0y1z2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("finding_retests") as batch:
        batch.add_column(sa.Column("scan_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("scanner_version", sa.String(50), nullable=True))
        batch.add_column(sa.Column("image_ref", sa.String(255), nullable=True))
        batch.add_column(sa.Column("image_digest", sa.String(128), nullable=True))
        batch.add_column(sa.Column("channel", sa.String(20), nullable=True))
        batch.add_column(sa.Column("baseline_fingerprint", sa.String(64), nullable=True))
        batch.add_column(sa.Column("resulting_fingerprint", sa.String(64), nullable=True))
        batch.add_column(sa.Column("fingerprint_algo", sa.String(20), nullable=True))
        batch.add_column(sa.Column("verification_note", sa.Text(), nullable=True))
    try:
        op.create_foreign_key(
            "fk_retest_scan",
            "finding_retests",
            "scans",
            ["scan_id"],
            ["id"],
            ondelete="SET NULL",
        )
    except Exception:
        pass
    for name, cols in (
        ("ix_retest_scan", ["scan_id"]),
        ("ix_retest_project_status", ["project_id", "status"]),
        ("ix_retest_finding_status", ["finding_id", "status"]),
        ("ix_retest_baseline_fp", ["baseline_fingerprint"]),
    ):
        try:
            op.create_index(name, "finding_retests", cols)
        except Exception:
            pass


def downgrade() -> None:
    for name in (
        "ix_retest_baseline_fp",
        "ix_retest_finding_status",
        "ix_retest_project_status",
        "ix_retest_scan",
    ):
        try:
            op.drop_index(name, table_name="finding_retests")
        except Exception:
            pass
    try:
        op.drop_constraint("fk_retest_scan", "finding_retests", type_="foreignkey")
    except Exception:
        pass
    with op.batch_alter_table("finding_retests") as batch:
        for col in (
            "verification_note",
            "fingerprint_algo",
            "resulting_fingerprint",
            "baseline_fingerprint",
            "channel",
            "image_digest",
            "image_ref",
            "scanner_version",
            "scan_id",
        ):
            try:
                batch.drop_column(col)
            except Exception:
                pass
