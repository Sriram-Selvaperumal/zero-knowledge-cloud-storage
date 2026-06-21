"""Create the initial users and file metadata schema.

Revision ID: 20260621_0001
Revises:
Create Date: 2026-06-21
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260621_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=50), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username")
    )
    op.create_index("ix_users_id", "users", ["id"], unique=False)

    op.create_table(
        "file_metadata",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("encrypted_filename", sa.String(length=1024), nullable=False),
        sa.Column("storage_key", sa.String(length=255), nullable=False),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("encryption_metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["owner_id"],
            ["users.id"],
            ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index(
        "ix_file_metadata_id",
        "file_metadata",
        ["id"],
        unique=False
    )
    op.create_index(
        "ix_file_metadata_owner_id",
        "file_metadata",
        ["owner_id"],
        unique=False
    )
    op.create_index(
        "ix_file_metadata_storage_key",
        "file_metadata",
        ["storage_key"],
        unique=True
    )


def downgrade() -> None:
    op.drop_index(
        "ix_file_metadata_storage_key",
        table_name="file_metadata"
    )
    op.drop_index("ix_file_metadata_owner_id", table_name="file_metadata")
    op.drop_index("ix_file_metadata_id", table_name="file_metadata")
    op.drop_table("file_metadata")
    op.drop_index("ix_users_id", table_name="users")
    op.drop_table("users")
