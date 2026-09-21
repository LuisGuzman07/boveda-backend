"""CU-08: encrypted file metadata and local MinIO replicas."""

from alembic import op
import sqlalchemy as sa


revision = "e00820260920"
down_revision = ("c00720260919", "d2b20260919")
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "archivo",
        sa.Column("id_archivo", sa.Uuid(), primary_key=True),
        sa.Column("id_boveda", sa.Uuid(), sa.ForeignKey("boveda.id_boveda"), nullable=False),
        sa.Column("nombre_cifrado", sa.JSON(), nullable=False),
        sa.Column("estado", sa.String(20), nullable=False),
        sa.Column("idempotency_key", sa.String(100), nullable=False),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("id_boveda", "idempotency_key", name="uq_archivo_reintento"),
        sa.CheckConstraint("estado IN ('ACTIVO', 'ELIMINADO')", name="ck_archivo_estado"),
    )
    op.create_index("ix_archivo_id_boveda", "archivo", ["id_boveda"])
    op.create_table(
        "version_archivo",
        sa.Column("id_version_archivo", sa.Uuid(), primary_key=True),
        sa.Column("id_archivo", sa.Uuid(), sa.ForeignKey("archivo.id_archivo"), nullable=False),
        sa.Column("id_boveda", sa.Uuid(), sa.ForeignKey("boveda.id_boveda"), nullable=False),
        sa.Column("numero_version", sa.Integer(), nullable=False),
        sa.Column("tamano_cifrado", sa.Integer(), nullable=False),
        sa.Column("hash_cifrado", sa.String(64), nullable=False),
        sa.Column("nonce_iv", sa.String(32), nullable=False),
        sa.Column("auth_tag", sa.String(32), nullable=False),
        sa.Column("algoritmo", sa.String(100), nullable=False),
        sa.Column("idempotency_key", sa.String(100), nullable=False),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("id_archivo", "numero_version", name="uq_archivo_version"),
        sa.UniqueConstraint("id_boveda", "idempotency_key", name="uq_version_archivo_reintento"),
    )
    op.create_index("ix_version_archivo_id_archivo", "version_archivo", ["id_archivo"])
    op.create_index("ix_version_archivo_id_boveda", "version_archivo", ["id_boveda"])
    op.add_column("clave_envuelta", sa.Column("id_version_archivo", sa.Uuid(), nullable=True))
    op.drop_constraint("uq_clave_destinatario", "clave_envuelta", type_="unique")
    op.create_foreign_key(
        "fk_clave_envuelta_version_archivo",
        "clave_envuelta",
        "version_archivo",
        ["id_version_archivo"],
        ["id_version_archivo"],
    )
    op.create_unique_constraint(
        "uq_clave_archivo_destinatario",
        "clave_envuelta",
        ["id_version_archivo", "id_usuario", "id_dispositivo", "version_clave"],
    )
    op.create_table(
        "replica_almacenamiento",
        sa.Column("id_replica", sa.Uuid(), primary_key=True),
        sa.Column("id_version_archivo", sa.Uuid(), sa.ForeignKey("version_archivo.id_version_archivo"), nullable=False),
        sa.Column("proveedor", sa.String(30), nullable=False),
        sa.Column("clave_objeto", sa.String(255), nullable=False, unique=True),
        sa.Column("estado", sa.String(30), nullable=False),
        sa.Column("etag", sa.String(128), nullable=True),
        sa.Column("hash_cifrado", sa.String(64), nullable=False),
        sa.Column("fecha_verificacion", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("id_version_archivo", "proveedor", name="uq_replica_version_proveedor"),
    )
    op.create_index("ix_replica_almacenamiento_id_version_archivo", "replica_almacenamiento", ["id_version_archivo"])


def downgrade():
    op.drop_index("ix_replica_almacenamiento_id_version_archivo", table_name="replica_almacenamiento")
    op.drop_table("replica_almacenamiento")
    op.drop_constraint("uq_clave_archivo_destinatario", "clave_envuelta", type_="unique")
    op.create_unique_constraint(
        "uq_clave_destinatario",
        "clave_envuelta",
        ["id_boveda", "id_usuario", "id_dispositivo", "version_clave"],
    )
    op.drop_constraint("fk_clave_envuelta_version_archivo", "clave_envuelta", type_="foreignkey")
    op.drop_column("clave_envuelta", "id_version_archivo")
    op.drop_index("ix_version_archivo_id_boveda", table_name="version_archivo")
    op.drop_index("ix_version_archivo_id_archivo", table_name="version_archivo")
    op.drop_table("version_archivo")
    op.drop_index("ix_archivo_id_boveda", table_name="archivo")
    op.drop_table("archivo")
