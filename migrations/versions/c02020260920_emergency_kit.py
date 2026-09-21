"""CU-20 encrypted Emergency Kit envelopes and lifecycle state."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision = "c02020260920"
down_revision = "b01520260920"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "kit_emergencia",
        sa.Column("id_kit", UUID(as_uuid=True), primary_key=True),
        sa.Column("id_boveda", UUID(as_uuid=True), sa.ForeignKey("boveda.id_boveda", ondelete="CASCADE"), nullable=False),
        sa.Column("id_usuario", UUID(as_uuid=True), sa.ForeignKey("usuario.id_usuario", ondelete="CASCADE"), nullable=False),
        sa.Column("version_kit", sa.Integer(), nullable=False),
        sa.Column("version_criptografica", sa.Integer(), nullable=False),
        sa.Column("algoritmo_kdf", sa.String(32), nullable=False),
        sa.Column("kdf_salt", sa.String(64), nullable=False),
        sa.Column("kdf_salt_boveda", sa.String(64), nullable=False),
        sa.Column("kdf_parametros", sa.JSON(), nullable=False),
        sa.Column("sobre_cifrado", sa.JSON(), nullable=False),
        sa.Column("huella_kit", sa.String(64), nullable=False),
        sa.Column("estado", sa.String(20), nullable=False, server_default="ACTIVO"),
        sa.Column("fecha_expiracion", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fecha_revocacion", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("id_boveda", "version_kit", name="uq_kit_emergencia_version"),
        sa.CheckConstraint("estado IN ('ACTIVO', 'REVOCADO')", name="ck_kit_emergencia_estado"),
    )
    op.create_index("ix_kit_emergencia_id_boveda", "kit_emergencia", ["id_boveda"])
    op.create_index("ix_kit_emergencia_id_usuario", "kit_emergencia", ["id_usuario"])
    op.create_index("ix_kit_emergencia_huella_kit", "kit_emergencia", ["huella_kit"])
    op.bulk_insert(
        sa.table(
            "politica_seguridad",
            sa.column("id_politica", UUID(as_uuid=True)), sa.column("codigo", sa.String()),
            sa.column("nombre", sa.String()), sa.column("valor", sa.String()),
            sa.column("descripcion", sa.Text()), sa.column("activa", sa.Boolean()),
        ),
        [{
            "id_politica": "11111111-1111-1111-1111-111111111107",
            "codigo": "EMERGENCY_KIT_ENABLED",
            "nombre": "Recuperación de bóveda mediante Emergency Kit",
            "valor": "true",
            "descripcion": "Autoriza la creación, exportación, revocación y recuperación local mediante sobres cifrados.",
            "activa": True,
        }],
    )


def downgrade():
    op.execute("DELETE FROM politica_seguridad WHERE codigo = 'EMERGENCY_KIT_ENABLED'")
    op.drop_index("ix_kit_emergencia_huella_kit", table_name="kit_emergencia")
    op.drop_index("ix_kit_emergencia_id_usuario", table_name="kit_emergencia")
    op.drop_index("ix_kit_emergencia_id_boveda", table_name="kit_emergencia")
    op.drop_table("kit_emergencia")
