"""add scan phase

Revision ID: ead3c4176891
Revises: 820a31008900
Create Date: 2026-08-28 13:06:12.136530

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "ead3c4176891"
down_revision: Union[str, Sequence[str], None] = "820a31008900"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add phase column to scans table."""

    op.add_column(
        "scans",
        sa.Column(
            "phase",
            sa.String(length=50),
            nullable=False,
            server_default="queued",
        ),
    )

    op.create_index(
        "ix_scans_phase",
        "scans",
        ["phase"],
        unique=False,
    )

    # Remove the server-side default after existing rows
    # have been populated with "queued".
    op.alter_column(
        "scans",
        "phase",
        server_default=None,
    )


def downgrade() -> None:
    """Remove phase column from scans table."""

    op.drop_index(
        "ix_scans_phase",
        table_name="scans",
    )

    op.drop_column(
        "scans",
        "phase",
    )