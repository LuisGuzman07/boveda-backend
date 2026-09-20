"""Store CU08 client-encrypted file upload intents and replicas.

Revision ID: d2b20260922
Revises: d2b20260921
"""

import uuid

from alembic import op
import sqlalchemy as sa


revision = "d2b20260922"
down_revision = "d2b20260921"
branch_labels = None
depends_on = None


def _grant_vault_write_permission() -> None:
    bind = op.get_bind()
    permission_id = bind.execute(
        sa.text("SELECT id_permiso FROM permiso WHERE codigo = 'vaults:write'")
    ).scalar_one_or_none()
    if permission_id is None:
        permission_id = uuid.uuid4()
        bind.execute(
            sa.text(
                """
                INSERT INTO permiso (id_permiso, codigo, nombre, descripcion)
                VALUES (:id_permiso, 'vaults:write', 'Cargar en Bóvedas',
                        'Permite iniciar y completar cargas cifradas')
                """
            ),
            {"id_permiso": permission_id},
        )
    for role_name in ("Administrador", "Miembro"):
        role_id = bind.execute(
            sa.text("SELECT id_rol FROM rol WHERE nombre = :role_name"),
            {"role_name": role_name},
        ).scalar_one_or_none()
        if role_id is not None:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO rol_permiso (id_rol, id_permiso)
                    VALUES (:id_rol, :id_permiso)
                    ON CONFLICT (id_rol, id_permiso) DO NOTHING
                    """
                ),
                {"id_rol": role_id, "id_permiso": permission_id},
            )


def upgrade() -> None:
    op.create_table(
        "archivo",
        sa.Column("id_archivo", sa.UUID(), nullable=False),
        sa.Column("id_boveda", sa.UUID(), nullable=False),
        sa.Column("id_creado_por", sa.UUID(), nullable=False),
        sa.Column("estado", sa.String(length=20), server_default="PENDING", nullable=False),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("fecha_actualizacion", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "estado IN ('PENDING', 'UPLOADING', 'AVAILABLE', 'FAILED', 'ABORTED')",
            name="ck_archivo_estado",
        ),
        sa.ForeignKeyConstraint(["id_boveda"], ["boveda.id_boveda"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["id_creado_por"], ["usuario.id_usuario"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id_archivo"),
    )
    op.create_index("ix_archivo_id_boveda", "archivo", ["id_boveda"])
    op.create_index("ix_archivo_id_creado_por", "archivo", ["id_creado_por"])
    op.create_index("ix_archivo_boveda_estado", "archivo", ["id_boveda", "estado"])

    op.create_table(
        "archivo_version",
        sa.Column("id_version", sa.UUID(), nullable=False),
        sa.Column("id_archivo", sa.UUID(), nullable=False),
        sa.Column("id_boveda", sa.UUID(), nullable=False),
        sa.Column("numero_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("id_usuario_origen", sa.UUID(), nullable=False),
        sa.Column("id_dispositivo_origen", sa.UUID(), nullable=False),
        sa.Column("id_sesion_boveda_origen", sa.UUID(), nullable=False),
        sa.Column("estado", sa.String(length=20), server_default="PENDING", nullable=False),
        sa.Column("version_criptografica", sa.Integer(), server_default="1", nullable=False),
        sa.Column("tamano_ciphertext_esperado", sa.Integer(), nullable=False),
        sa.Column("tamano_ciphertext", sa.Integer(), nullable=True),
        sa.Column("checksum_ciphertext_sha256", sa.String(length=64), nullable=True),
        sa.Column("contenido_cifrado", sa.JSON(), nullable=True),
        sa.Column("clave_archivo_envuelta", sa.JSON(), nullable=True),
        sa.Column("metadata_cifrada", sa.JSON(), nullable=True),
        sa.Column("idempotency_key", sa.String(length=100), nullable=False),
        sa.Column("solicitud_hash", sa.String(length=64), nullable=False),
        sa.Column("complete_idempotency_key", sa.String(length=100), nullable=True),
        sa.Column("complete_solicitud_hash", sa.String(length=64), nullable=True),
        sa.Column("abort_idempotency_key", sa.String(length=100), nullable=True),
        sa.Column("fecha_expiracion", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fecha_completado", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("fecha_actualizacion", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "estado IN ('PENDING', 'UPLOADING', 'AVAILABLE', 'FAILED', 'ABORTED')",
            name="ck_archivo_version_estado",
        ),
        sa.CheckConstraint(
            "tamano_ciphertext_esperado >= 0",
            name="ck_archivo_version_tamano_esperado",
        ),
        sa.CheckConstraint(
            "tamano_ciphertext IS NULL OR tamano_ciphertext >= 0",
            name="ck_archivo_version_tamano_final",
        ),
        sa.CheckConstraint(
            "estado <> 'AVAILABLE' OR (tamano_ciphertext IS NOT NULL "
            "AND checksum_ciphertext_sha256 IS NOT NULL "
            "AND contenido_cifrado IS NOT NULL "
            "AND clave_archivo_envuelta IS NOT NULL "
            "AND metadata_cifrada IS NOT NULL)",
            name="ck_archivo_version_material_disponible",
        ),
        sa.ForeignKeyConstraint(["id_archivo"], ["archivo.id_archivo"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["id_boveda"], ["boveda.id_boveda"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["id_usuario_origen"], ["usuario.id_usuario"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["id_dispositivo_origen"], ["dispositivo.id_dispositivo"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["id_sesion_boveda_origen"],
            ["sesion_boveda.id_sesion_boveda"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id_version"),
        sa.UniqueConstraint("id_archivo", "numero_version", name="uq_archivo_version_numero"),
        sa.UniqueConstraint(
            "id_boveda",
            "id_usuario_origen",
            "idempotency_key",
            name="uq_archivo_version_reintento",
        ),
    )
    op.create_index("ix_archivo_version_id_archivo", "archivo_version", ["id_archivo"])
    op.create_index("ix_archivo_version_id_boveda", "archivo_version", ["id_boveda"])
    op.create_index("ix_archivo_version_id_usuario_origen", "archivo_version", ["id_usuario_origen"])
    op.create_index("ix_archivo_version_id_dispositivo_origen", "archivo_version", ["id_dispositivo_origen"])
    op.create_index("ix_archivo_version_id_sesion_boveda_origen", "archivo_version", ["id_sesion_boveda_origen"])
    op.create_index(
        "ix_archivo_version_expiracion", "archivo_version", ["estado", "fecha_expiracion"]
    )

    op.create_table(
        "replica_archivo",
        sa.Column("id_replica", sa.UUID(), nullable=False),
        sa.Column("id_version", sa.UUID(), nullable=False),
        sa.Column("proveedor", sa.String(length=20), server_default="MINIO", nullable=False),
        sa.Column("bucket", sa.String(length=63), nullable=False),
        sa.Column("object_key", sa.String(length=128), nullable=False),
        sa.Column("staging_object_key", sa.String(length=128), nullable=True),
        sa.Column("etag", sa.String(length=128), nullable=True),
        sa.Column("estado", sa.String(length=20), server_default="PENDING", nullable=False),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("fecha_actualizacion", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("proveedor IN ('MINIO', 'S3')", name="ck_replica_archivo_proveedor"),
        sa.CheckConstraint(
            "estado IN ('PENDING', 'UPLOADING', 'AVAILABLE', 'FAILED', 'ABORTED')",
            name="ck_replica_archivo_estado",
        ),
        sa.ForeignKeyConstraint(
            ["id_version"], ["archivo_version.id_version"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id_replica"),
        sa.UniqueConstraint("id_version", "proveedor", name="uq_replica_archivo_proveedor"),
        sa.UniqueConstraint("bucket", "object_key", name="uq_replica_archivo_objeto"),
        sa.UniqueConstraint("bucket", "staging_object_key", name="uq_replica_archivo_staging"),
    )
    op.create_index("ix_replica_archivo_id_version", "replica_archivo", ["id_version"])
    _grant_vault_write_permission()


def downgrade() -> None:
    op.drop_index("ix_replica_archivo_id_version", table_name="replica_archivo")
    op.drop_table("replica_archivo")
    op.drop_index("ix_archivo_version_expiracion", table_name="archivo_version")
    op.drop_index("ix_archivo_version_id_sesion_boveda_origen", table_name="archivo_version")
    op.drop_index("ix_archivo_version_id_dispositivo_origen", table_name="archivo_version")
    op.drop_index("ix_archivo_version_id_usuario_origen", table_name="archivo_version")
    op.drop_index("ix_archivo_version_id_boveda", table_name="archivo_version")
    op.drop_index("ix_archivo_version_id_archivo", table_name="archivo_version")
    op.drop_table("archivo_version")
    op.drop_index("ix_archivo_boveda_estado", table_name="archivo")
    op.drop_index("ix_archivo_id_creado_por", table_name="archivo")
    op.drop_index("ix_archivo_id_boveda", table_name="archivo")
    op.drop_table("archivo")

    bind = op.get_bind()
    permission_id = bind.execute(
        sa.text("SELECT id_permiso FROM permiso WHERE codigo = 'vaults:write'")
    ).scalar_one_or_none()
    if permission_id is None:
        return
    for role_name in ("Administrador", "Miembro"):
        bind.execute(
            sa.text(
                """
                DELETE FROM rol_permiso
                WHERE id_permiso = :permission_id
                  AND id_rol IN (SELECT id_rol FROM rol WHERE nombre = :role_name)
                """
            ),
            {"permission_id": permission_id, "role_name": role_name},
        )
    bind.execute(
        sa.text(
            """
            DELETE FROM permiso
            WHERE id_permiso = :permission_id
              AND NOT EXISTS (
                  SELECT 1 FROM rol_permiso WHERE id_permiso = :permission_id
              )
            """
        ),
        {"permission_id": permission_id},
    )
