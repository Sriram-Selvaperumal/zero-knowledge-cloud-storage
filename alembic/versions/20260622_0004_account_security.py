"""Add account recovery, refresh sessions, and login throttles.

Revision ID: 20260622_0004
Revises: 20260621_0003
Create Date: 2026-06-22
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260622_0004"
down_revision: str | None = "20260621_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "auth_version",
            sa.Integer(),
            server_default="1",
            nullable=False
        )
    )
    op.alter_column("users", "auth_version", server_default=None)

    op.add_column(
        "user_crypto_profiles",
        sa.Column("recovery_version", sa.Integer(), nullable=True)
    )
    op.add_column(
        "user_crypto_profiles",
        sa.Column(
            "recovery_wrap_algorithm",
            sa.String(length=100),
            nullable=True
        )
    )
    op.add_column(
        "user_crypto_profiles",
        sa.Column(
            "recovery_wrapped_vault_key",
            sa.String(length=512),
            nullable=True
        )
    )
    op.add_column(
        "user_crypto_profiles",
        sa.Column(
            "recovery_wrap_nonce",
            sa.String(length=128),
            nullable=True
        )
    )

    op.create_table(
        "authentication_throttles",
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("window_started_at", sa.DateTime(), nullable=False),
        sa.Column("blocked_until", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("key_hash")
    )
    op.create_index(
        op.f("ix_authentication_throttles_blocked_until"),
        "authentication_throttles",
        ["blocked_until"],
        unique=False
    )

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("refresh_token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index(
        op.f("ix_user_sessions_expires_at"),
        "user_sessions",
        ["expires_at"],
        unique=False
    )
    op.create_index(
        op.f("ix_user_sessions_revoked_at"),
        "user_sessions",
        ["revoked_at"],
        unique=False
    )
    op.create_index(
        op.f("ix_user_sessions_user_id"),
        "user_sessions",
        ["user_id"],
        unique=False
    )

    op.create_table(
        "password_recovery_verifications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("identifier_hash", sa.String(length=64), nullable=False),
        sa.Column("otp_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("attempts_remaining", sa.Integer(), nullable=False),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("grant_expires_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("identifier_hash")
    )
    op.create_index(
        op.f("ix_password_recovery_verifications_expires_at"),
        "password_recovery_verifications",
        ["expires_at"],
        unique=False
    )
    op.create_index(
        op.f("ix_password_recovery_verifications_user_id"),
        "password_recovery_verifications",
        ["user_id"],
        unique=False
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_password_recovery_verifications_user_id"),
        table_name="password_recovery_verifications"
    )
    op.drop_index(
        op.f("ix_password_recovery_verifications_expires_at"),
        table_name="password_recovery_verifications"
    )
    op.drop_table("password_recovery_verifications")

    op.drop_index(
        op.f("ix_user_sessions_user_id"),
        table_name="user_sessions"
    )
    op.drop_index(
        op.f("ix_user_sessions_revoked_at"),
        table_name="user_sessions"
    )
    op.drop_index(
        op.f("ix_user_sessions_expires_at"),
        table_name="user_sessions"
    )
    op.drop_table("user_sessions")

    op.drop_index(
        op.f("ix_authentication_throttles_blocked_until"),
        table_name="authentication_throttles"
    )
    op.drop_table("authentication_throttles")

    op.drop_column("user_crypto_profiles", "recovery_wrap_nonce")
    op.drop_column("user_crypto_profiles", "recovery_wrapped_vault_key")
    op.drop_column("user_crypto_profiles", "recovery_wrap_algorithm")
    op.drop_column("user_crypto_profiles", "recovery_version")
    op.drop_column("users", "auth_version")
