"""Add password-protected encrypted file shares.

Revision ID: 20260623_0005
Revises: 20260622_0004
Create Date: 2026-06-23
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260623_0005"
down_revision: str | None = "20260622_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "file_shares",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("file_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("kdf_algorithm", sa.String(length=50), nullable=False),
        sa.Column("kdf_salt", sa.String(length=128), nullable=False),
        sa.Column("kdf_parameters", sa.JSON(), nullable=False),
        sa.Column("wrap_algorithm", sa.String(length=100), nullable=False),
        sa.Column("wrapped_file_key", sa.String(length=512), nullable=False),
        sa.Column("wrap_nonce", sa.String(length=128), nullable=False),
        sa.Column("password_verifier", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["file_id"],
            ["file_metadata.id"],
            ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index(
        op.f("ix_file_shares_expires_at"),
        "file_shares",
        ["expires_at"],
        unique=False
    )
    op.create_index(
        op.f("ix_file_shares_file_id"),
        "file_shares",
        ["file_id"],
        unique=False
    )
    op.create_index(
        op.f("ix_file_shares_revoked_at"),
        "file_shares",
        ["revoked_at"],
        unique=False
    )
    op.create_index(
        op.f("ix_file_shares_token_hash"),
        "file_shares",
        ["token_hash"],
        unique=True
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_file_shares_token_hash"), table_name="file_shares")
    op.drop_index(op.f("ix_file_shares_revoked_at"), table_name="file_shares")
    op.drop_index(op.f("ix_file_shares_file_id"), table_name="file_shares")
    op.drop_index(op.f("ix_file_shares_expires_at"), table_name="file_shares")
    op.drop_table("file_shares")
