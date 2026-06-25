"""Add refresh token reuse grace metadata.

Revision ID: 20260625_0006
Revises: 20260623_0005
Create Date: 2026-06-25
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260625_0006"
down_revision: str | None = "20260623_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "user_sessions",
        sa.Column(
            "previous_refresh_token_hash",
            sa.String(length=64),
            nullable=True
        )
    )
    op.add_column(
        "user_sessions",
        sa.Column(
            "previous_refresh_token_expires_at",
            sa.DateTime(),
            nullable=True
        )
    )


def downgrade() -> None:
    op.drop_column("user_sessions", "previous_refresh_token_expires_at")
    op.drop_column("user_sessions", "previous_refresh_token_hash")
