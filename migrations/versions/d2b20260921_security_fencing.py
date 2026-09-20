"""Fence session security state and preserve terminal device identities.

Revision ID: d2b20260921
Revises: d2b20260920
"""

import hashlib
import uuid

from alembic import context, op
import sqlalchemy as sa


revision = "d2b20260921"
down_revision = "d2b20260920"
branch_labels = None
depends_on = None


def _sync_role_permissions() -> None:
    """Apply the authorization split to existing installations, not only fresh seeds."""
    bind = op.get_bind()
    permissions = {
        "devices:approve": (
            "Aprobar Dispositivos",
            "Permite aprobar identidades de dispositivo verificadas",
        ),
        "audit:export": (
            "Exportar Auditoría",
            "Permite exportar reportes de seguridad",
        ),
    }
    for code, (name, description) in permissions.items():
        permission_id = bind.execute(
            sa.text("SELECT id_permiso FROM permiso WHERE codigo = :code"),
            {"code": code},
        ).scalar_one_or_none()
        if permission_id is None:
            permission_id = uuid.uuid4()
            bind.execute(
                sa.text(
                    """
                    INSERT INTO permiso (id_permiso, codigo, nombre, descripcion)
                    VALUES (:id_permiso, :codigo, :nombre, :descripcion)
                    """
                ),
                {
                    "id_permiso": permission_id,
                    "codigo": code,
                    "nombre": name,
                    "descripcion": description,
                },
            )

    auditor_id = bind.execute(
        sa.text("SELECT id_rol FROM rol WHERE nombre = 'Auditor'")
    ).scalar_one_or_none()
    export_id = bind.execute(
        sa.text("SELECT id_permiso FROM permiso WHERE codigo = 'audit:export'")
    ).scalar_one()
    if auditor_id is not None:
        bind.execute(
            sa.text(
                "DELETE FROM rol_permiso WHERE id_rol = :role_id AND id_permiso = :permission_id"
            ),
            {"role_id": auditor_id, "permission_id": export_id},
        )

    admin_id = bind.execute(
        sa.text("SELECT id_rol FROM rol WHERE nombre = 'Administrador'")
    ).scalar_one_or_none()
    if admin_id is not None:
        for code in ("devices:approve", "audit:export"):
            permission_id = bind.execute(
                sa.text("SELECT id_permiso FROM permiso WHERE codigo = :code"),
                {"code": code},
            ).scalar_one()
            bind.execute(
                sa.text(
                    """
                    INSERT INTO rol_permiso (id_rol, id_permiso)
                    VALUES (:role_id, :permission_id)
                    ON CONFLICT (id_rol, id_permiso) DO NOTHING
                    """
                ),
                {"role_id": admin_id, "permission_id": permission_id},
            )


def _backfill_device_identity_claims() -> None:
    bind = op.get_bind()
    devices = bind.execute(
        sa.text(
            """
            SELECT id_dispositivo, identificador_seguro, huella_clave_publica
            FROM dispositivo
            """
        )
    ).mappings()
    for device in devices:
        claims = [("INSTALLATION_ID", device["identificador_seguro"])]
        if device["huella_clave_publica"]:
            claims.append(("DEVICE_KEY", device["huella_clave_publica"]))
        for claim_type, fingerprint in claims:
            if claim_type == "INSTALLATION_ID":
                fingerprint = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
            bind.execute(
                sa.text(
                    """
                    INSERT INTO identidad_dispositivo (
                        id_identidad, id_dispositivo, tipo, huella
                    ) VALUES (:id_identidad, :id_dispositivo, :tipo, :huella)
                    """
                ),
                {
                    "id_identidad": uuid.uuid4(),
                    "id_dispositivo": device["id_dispositivo"],
                    "tipo": claim_type,
                    "huella": fingerprint,
                },
            )


def _assert_global_device_identity_uniqueness() -> None:
    """Do not silently assign a permanent claim to only one duplicate legacy device."""
    bind = op.get_bind()
    duplicate_installation = bind.execute(
        sa.text(
            """
            SELECT identificador_seguro
            FROM dispositivo
            GROUP BY identificador_seguro
            HAVING COUNT(*) > 1
            LIMIT 1
            """
        )
    ).scalar_one_or_none()
    duplicate_key = bind.execute(
        sa.text(
            """
            SELECT huella_clave_publica
            FROM dispositivo
            WHERE huella_clave_publica IS NOT NULL
            GROUP BY huella_clave_publica
            HAVING COUNT(*) > 1
            LIMIT 1
            """
        )
    ).scalar_one_or_none()
    if duplicate_installation or duplicate_key:
        raise RuntimeError(
            "La migracion requiere identidades de dispositivo globalmente unicas. "
            "Resuelve los identificadores o huellas duplicados antes de reintentarla."
        )


def upgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "This migration backfills security state and must run online."
        )

    op.add_column(
        "usuario",
        sa.Column("version_seguridad", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "sesion",
        sa.Column("version_seguridad", sa.Integer(), server_default="0", nullable=False),
    )
    _assert_global_device_identity_uniqueness()
    op.create_table(
        "identidad_dispositivo",
        sa.Column("id_identidad", sa.UUID(), nullable=False),
        sa.Column("id_dispositivo", sa.UUID(), nullable=False),
        sa.Column("tipo", sa.String(length=30), nullable=False),
        sa.Column("huella", sa.String(length=64), nullable=False),
        sa.Column("fecha_registro", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["id_dispositivo"], ["dispositivo.id_dispositivo"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id_identidad"),
        sa.UniqueConstraint("tipo", "huella", name="uq_identidad_dispositivo_tipo_huella"),
    )
    _backfill_device_identity_claims()
    _sync_role_permissions()


def downgrade() -> None:
    raise RuntimeError(
        "Downgrade is disabled because it would reopen revoked device identities and stale sessions. "
        "Restore a database backup instead."
    )
