"""add enterprise audit D10 integrity columns + query indexes

Revision ID: x0y1z2a3b4c5
Revises: w9x0y1z2a3b4
Create Date: 2026-09-10

D10 (Enterprise Audit) schema, additive only:

- audit_logs.prev_hash / event_hash (nullable: historical rows and
  best-effort failures stay readable/unchained)
- composite index (organization_id, created_at) for scoped chain-tip lookup
- index on event_hash for prev-link existence checks
- index on correlation_id for the correlation filter
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "x0y1z2a3b4c5"
down_revision: Union[str, Sequence[str], None] = "w9x0y1z2a3b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("audit_logs") as batch:
        batch.add_column(sa.Column("prev_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("event_hash", sa.String(64), nullable=True))
    for name, cols in (
        ("ix_audit_logs_org_created", ["organization_id", "created_at"]),
        ("ix_audit_logs_event_hash", ["event_hash"]),
        ("ix_audit_logs_correlation_id", ["correlation_id"]),
    ):
        try:
            op.create_index(name, "audit_logs", cols)
        except Exception:
            pass


def downgrade() -> None:
    for name in (
        "ix_audit_logs_correlation_id",
        "ix_audit_logs_event_hash",
        "ix_audit_logs_org_created",
    ):
        try:
            op.drop_index(name, table_name="audit_logs")
        except Exception:
            pass
    with op.batch_alter_table("audit_logs") as batch:
        for col in ("event_hash", "prev_hash"):
            try:
                batch.drop_column(col)
            except Exception:
                pass
