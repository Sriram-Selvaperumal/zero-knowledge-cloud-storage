"""Add encrypted vault folders.

Revision ID: 20260629_0007
Revises: 20260625_0006
Create Date: 2026-06-29
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260629_0007"
down_revision: str | None = "20260625_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "folder_metadata",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("parent_id", sa.Integer(), nullable=True),
        sa.Column("encrypted_name", sa.String(length=1024), nullable=False),
        sa.Column("encryption_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["owner_id"],
            ["users.id"],
            ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["parent_id"],
            ["folder_metadata.id"],
            ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index(
        op.f("ix_folder_metadata_id"),
        "folder_metadata",
        ["id"],
        unique=False
    )
    op.create_index(
        op.f("ix_folder_metadata_owner_id"),
        "folder_metadata",
        ["owner_id"],
        unique=False
    )
    op.create_index(
        op.f("ix_folder_metadata_parent_id"),
        "folder_metadata",
        ["parent_id"],
        unique=False
    )

    op.add_column(
        "file_metadata",
        sa.Column("folder_id", sa.Integer(), nullable=True)
    )
    op.create_index(
        op.f("ix_file_metadata_folder_id"),
        "file_metadata",
        ["folder_id"],
        unique=False
    )
    op.create_foreign_key(
        "fk_file_metadata_folder_id_folder_metadata",
        "file_metadata",
        "folder_metadata",
        ["folder_id"],
        ["id"],
        ondelete="SET NULL"
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_file_metadata_folder_id_folder_metadata",
        "file_metadata",
        type_="foreignkey"
    )
    op.drop_index(
        op.f("ix_file_metadata_folder_id"),
        table_name="file_metadata"
    )
    op.drop_column("file_metadata", "folder_id")

    op.drop_index(op.f("ix_folder_metadata_parent_id"), table_name="folder_metadata")
    op.drop_index(op.f("ix_folder_metadata_owner_id"), table_name="folder_metadata")
    op.drop_index(op.f("ix_folder_metadata_id"), table_name="folder_metadata")
    op.drop_table("folder_metadata")
