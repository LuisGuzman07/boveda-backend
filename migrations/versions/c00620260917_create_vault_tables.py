"""CU-06: contenedor, membresía y claves protegidas."""
from alembic import op
import sqlalchemy as sa

revision = "c00620260917"
down_revision = "88147b01c815"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("boveda",
        sa.Column("id_boveda", sa.Uuid(), primary_key=True),
        sa.Column("id_propietario", sa.Uuid(), sa.ForeignKey("usuario.id_usuario"), nullable=False),
        sa.Column("nombre_cifrado", sa.JSON(), nullable=False),
        sa.Column("descripcion_cifrada", sa.JSON(), nullable=True),
        sa.Column("version_criptografica", sa.Integer(), nullable=False),
        sa.Column("kdf_salt", sa.String(64), nullable=False),
        sa.Column("kdf_parametros", sa.JSON(), nullable=False),
        sa.Column("estado", sa.String(20), nullable=False),
        sa.Column("idempotency_key", sa.String(100), nullable=False),
        sa.Column("solicitud_hash", sa.String(64), nullable=False),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("fecha_actualizacion", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("id_propietario", "idempotency_key", name="uq_boveda_reintento"),
        sa.CheckConstraint("estado IN ('ACTIVA', 'ELIMINADA')", name="ck_boveda_estado"))
    op.create_index("ix_boveda_id_propietario", "boveda", ["id_propietario"])
    op.create_table("membresia_boveda",
        sa.Column("id_boveda", sa.Uuid(), sa.ForeignKey("boveda.id_boveda"), primary_key=True),
        sa.Column("id_usuario", sa.Uuid(), sa.ForeignKey("usuario.id_usuario"), primary_key=True),
        sa.Column("rol_boveda", sa.String(30), nullable=False),
        sa.Column("estado", sa.String(20), nullable=False),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("id_boveda", "id_usuario", name="uq_membresia_boveda_usuario"),
        sa.CheckConstraint("estado IN ('ACTIVA', 'REVOCADA')", name="ck_membresia_estado"))
    op.create_table("clave_envuelta",
        sa.Column("id_clave_envuelta", sa.Uuid(), primary_key=True),
        sa.Column("id_boveda", sa.Uuid(), sa.ForeignKey("boveda.id_boveda"), nullable=False),
        sa.Column("id_usuario", sa.Uuid(), sa.ForeignKey("usuario.id_usuario"), nullable=False),
        sa.Column("id_dispositivo", sa.Uuid(), sa.ForeignKey("dispositivo.id_dispositivo"), nullable=False),
        sa.Column("algoritmo", sa.String(100), nullable=False),
        sa.Column("ciphertext", sa.String(2048), nullable=False),
        sa.Column("nonce", sa.String(32), nullable=False),
        sa.Column("tag", sa.String(32), nullable=False),
        sa.Column("version_clave", sa.Integer(), nullable=False),
        sa.Column("estado", sa.String(20), nullable=False),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("id_boveda", "id_usuario", "id_dispositivo", "version_clave", name="uq_clave_destinatario"),
        sa.CheckConstraint("estado IN ('ACTIVA', 'REVOCADA')", name="ck_clave_estado"))


def downgrade():
    op.drop_table("clave_envuelta")
    op.drop_table("membresia_boveda")
    op.drop_index("ix_boveda_id_propietario", table_name="boveda")
    op.drop_table("boveda")
