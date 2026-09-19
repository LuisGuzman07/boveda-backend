"""Encrypt persisted TOTP secrets.

Revision ID: f2a1b3c4d5e6
Revises: c00620260917
"""

from alembic import context, op
import sqlalchemy as sa


revision = "f2a1b3c4d5e6"
down_revision = "c00620260917"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "autenticador_mfa",
        sa.Column("secreto_cifrado_v2", sa.Text(), nullable=True),
    )
    op.add_column(
        "autenticador_mfa",
        sa.Column("version_criptografica", sa.Integer(), nullable=True),
    )
    op.alter_column(
        "autenticador_mfa",
        "secreto_cifrado",
        existing_type=sa.String(length=255),
        nullable=True,
    )

    # Offline SQL documents only the schema. Encrypting data requires the runtime key.
    if context.is_offline_mode():
        return

    from app.services.totp_secret_service import migrate_legacy_totp_secrets

    migrate_legacy_totp_secrets(op.get_bind())


def downgrade() -> None:
    raise RuntimeError(
        "Downgrade is disabled because it could discard encrypted TOTP material."
    )
