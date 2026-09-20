"""Require explicit administrative approval for trusted devices.

Revision ID: d2b20260920
Revises: d2b20260919
"""

from alembic import op
import sqlalchemy as sa


revision = "d2b20260920"
down_revision = "d2b20260919"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dispositivo",
        sa.Column("confianza_otorgada_por", sa.UUID(), nullable=True),
    )
    op.create_foreign_key(
        "fk_dispositivo_confianza_otorgada_por_usuario",
        "dispositivo",
        "usuario",
        ["confianza_otorgada_por"],
        ["id_usuario"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_dispositivo_estado_identificador",
        "dispositivo",
        ["estado", "identificador_seguro"],
    )
    op.create_index(
        "ix_dispositivo_estado_huella_clave",
        "dispositivo",
        ["estado", "huella_clave_publica"],
    )
    # Existing TRUSTED rows have no independent administrative approval evidence.
    op.execute(
        """
        UPDATE dispositivo
        SET estado = 'PENDING',
            es_confiable = FALSE,
            confianza_otorgada_en = NULL,
            confianza_otorgada_por = NULL
        WHERE estado = 'TRUSTED'
        """
    )


def downgrade() -> None:
    raise RuntimeError(
        "Downgrade is disabled because it would restore trust without independent approval evidence. "
        "Restore a database backup instead."
    )
