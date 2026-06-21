"""Add pending registration email verifications.

Revision ID: 20260621_0003
Revises: 20260621_0002
Create Date: 2026-06-21
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260621_0003"
down_revision: str | None = "20260621_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "registration_verifications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("username", sa.String(length=50), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("otp_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("attempts_remaining", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index(
        op.f("ix_registration_verifications_email"),
        "registration_verifications",
        ["email"],
        unique=True
    )
    op.create_index(
        op.f("ix_registration_verifications_expires_at"),
        "registration_verifications",
        ["expires_at"],
        unique=False
    )
    op.create_index(
        op.f("ix_registration_verifications_username"),
        "registration_verifications",
        ["username"],
        unique=True
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_registration_verifications_username"),
        table_name="registration_verifications"
    )
    op.drop_index(
        op.f("ix_registration_verifications_expires_at"),
        table_name="registration_verifications"
    )
    op.drop_index(
        op.f("ix_registration_verifications_email"),
        table_name="registration_verifications"
    )
    op.drop_table("registration_verifications")
