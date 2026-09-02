"""merge scan created_at and findings branches

Revision ID: d7c4e91f2a08
Revises: 6715084468e9, ead3c4176891
Create Date: 2026-09-02 23:10:00.000000

"""
from typing import Sequence, Union


revision: str = "d7c4e91f2a08"
down_revision: Union[str, Sequence[str], None] = (
    "6715084468e9",
    "ead3c4176891",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Schema from both branches is already present."""


def downgrade() -> None:
    """Schema from both branches is already present."""
