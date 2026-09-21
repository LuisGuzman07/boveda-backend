"""CU-18/CU-19 temporary encrypted sharing and revocation."""

from alembic import op
import sqlalchemy as sa


revision = "f01820260921"
down_revision = "d01120260921"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "acceso_compartido",
        sa.Column("id_acceso_compartido", sa.Uuid(), primary_key=True),
        sa.Column("id_boveda", sa.Uuid(), sa.ForeignKey("boveda.id_boveda"), nullable=True),
        sa.Column("id_archivo", sa.Uuid(), sa.ForeignKey("archivo.id_archivo"), nullable=True),
        sa.Column("id_destinatario", sa.Uuid(), sa.ForeignKey("usuario.id_usuario"), nullable=False),
        sa.Column("id_otorgante", sa.Uuid(), sa.ForeignKey("usuario.id_usuario"), nullable=False),
        sa.Column("permiso", sa.String(20), nullable=False, server_default="LECTURA"),
        sa.Column("inicia_en", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("expira_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column("estado", sa.String(20), nullable=False, server_default="ACTIVO"),
        sa.Column("revocado_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocado_por", sa.Uuid(), sa.ForeignKey("usuario.id_usuario"), nullable=True),
        sa.Column("motivo_revocacion", sa.String(255), nullable=True),
        sa.Column("epoca_clave", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("version_clave", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("idempotency_key", sa.String(100), nullable=False),
        sa.Column("solicitud_hash", sa.String(64), nullable=False),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("(id_boveda IS NOT NULL AND id_archivo IS NULL) OR (id_boveda IS NULL AND id_archivo IS NOT NULL)", name="ck_acceso_compartido_un_alcance"),
        sa.CheckConstraint("permiso IN ('LECTURA')", name="ck_acceso_compartido_permiso"),
        sa.CheckConstraint("estado IN ('ACTIVO', 'REVOCADO')", name="ck_acceso_compartido_estado"),
        sa.UniqueConstraint("id_otorgante", "idempotency_key", name="uq_acceso_compartido_reintento"),
    )
    op.create_index("ix_acceso_compartido_destinatario", "acceso_compartido", ["id_destinatario"])
    op.create_index("ix_acceso_compartido_boveda", "acceso_compartido", ["id_boveda"])
    op.create_index("ix_acceso_compartido_archivo", "acceso_compartido", ["id_archivo"])
    op.create_table(
        "sobre_acceso_compartido",
        sa.Column("id_sobre_acceso", sa.Uuid(), primary_key=True),
        sa.Column("id_acceso_compartido", sa.Uuid(), sa.ForeignKey("acceso_compartido.id_acceso_compartido", ondelete="CASCADE"), nullable=False),
        sa.Column("id_dispositivo_destinatario", sa.Uuid(), sa.ForeignKey("dispositivo.id_dispositivo"), nullable=False),
        sa.Column("algoritmo", sa.String(100), nullable=False),
        sa.Column("ciphertext", sa.String(4096), nullable=False),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column("tag", sa.String(64), nullable=False),
        sa.Column("huella_identidad_destinatario", sa.String(64), nullable=False),
        sa.Column("epoca_clave", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("version_clave", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("estado", sa.String(20), nullable=False, server_default="ACTIVO"),
        sa.Column("revocado_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("id_acceso_compartido", "id_dispositivo_destinatario", name="uq_sobre_acceso_dispositivo"),
        sa.CheckConstraint("estado IN ('ACTIVO', 'REVOCADO')", name="ck_sobre_acceso_estado"),
    )
    op.create_index("ix_sobre_acceso_dispositivo", "sobre_acceso_compartido", ["id_dispositivo_destinatario"])


def downgrade():
    op.drop_index("ix_sobre_acceso_dispositivo", table_name="sobre_acceso_compartido")
    op.drop_table("sobre_acceso_compartido")
    op.drop_index("ix_acceso_compartido_archivo", table_name="acceso_compartido")
    op.drop_index("ix_acceso_compartido_boveda", table_name="acceso_compartido")
    op.drop_index("ix_acceso_compartido_destinatario", table_name="acceso_compartido")
    op.drop_table("acceso_compartido")
