"""Add client-managed user crypto profiles.

Revision ID: 20260621_0002
Revises: 20260621_0001
Create Date: 2026-06-21
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260621_0002"
down_revision: str | None = "20260621_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user_crypto_profiles",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("kdf_algorithm", sa.String(length=50), nullable=False),
        sa.Column("kdf_salt", sa.String(length=128), nullable=False),
        sa.Column("kdf_parameters", sa.JSON(), nullable=False),
        sa.Column("wrap_algorithm", sa.String(length=100), nullable=False),
        sa.Column("wrapped_vault_key", sa.String(length=512), nullable=False),
        sa.Column("wrap_nonce", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("user_id")
    )


def downgrade() -> None:
    op.drop_table("user_crypto_profiles")
