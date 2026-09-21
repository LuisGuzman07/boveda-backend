"""Add versioned global security policies after CU08.

Revision ID: d2b20260923
Revises: d2b20260922
"""

import uuid

from alembic import op
import sqlalchemy as sa


revision = "d2b20260923"
down_revision = "d2b20260922"
branch_labels = None
depends_on = None


POLICIES = (
    ("INACTIVITY_TIMEOUT_MINUTES", 15),
    ("MAX_FAILED_LOGIN_ATTEMPTS", 5),
    ("LOCKOUT_DURATION_MINUTES", 15),
    # Preserve CU08's short-lived server capability rather than lengthening it.
    ("VAULT_SESSION_DURATION_MINUTES", 5),
    ("PASSWORD_MIN_LENGTH", 12),
    ("AUDIT_RETENTION_DAYS", 90),
)


def _sync_policy_permissions() -> None:
    bind = op.get_bind()
    permissions = {
        "policies:read": (
            "Consultar Políticas",
            "Permite consultar políticas globales de seguridad",
        ),
        "policies:write": (
            "Actualizar Políticas",
            "Permite actualizar políticas globales de seguridad",
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

    administrator_id = bind.execute(
        sa.text("SELECT id_rol FROM rol WHERE nombre = 'Administrador'")
    ).scalar_one_or_none()
    if administrator_id is None:
        return
    for code in permissions:
        permission_id = bind.execute(
            sa.text("SELECT id_permiso FROM permiso WHERE codigo = :code"),
            {"code": code},
        ).scalar_one()
        bind.execute(
            sa.text(
                """
                INSERT INTO rol_permiso (id_rol, id_permiso)
                VALUES (:id_rol, :id_permiso)
                ON CONFLICT (id_rol, id_permiso) DO NOTHING
                """
            ),
            {"id_rol": administrator_id, "id_permiso": permission_id},
        )


def _seed_policies() -> None:
    bind = op.get_bind()
    for code, value in POLICIES:
        existing = bind.execute(
            sa.text("SELECT id_politica FROM politica_seguridad WHERE codigo = :code"),
            {"code": code},
        ).scalar_one_or_none()
        if existing is None:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO politica_seguridad (
                        id_politica, codigo, tipo_valor, valor_entero, activa, version
                    ) VALUES (:id_politica, :codigo, 'INTEGER', :valor_entero, TRUE, 1)
                    """
                ),
                {"id_politica": uuid.uuid4(), "codigo": code, "valor_entero": value},
            )


def upgrade() -> None:
    op.create_table(
        "politica_seguridad",
        sa.Column("id_politica", sa.UUID(), nullable=False),
        sa.Column("codigo", sa.String(length=100), nullable=False),
        sa.Column("tipo_valor", sa.String(length=20), server_default="INTEGER", nullable=False),
        sa.Column("valor_entero", sa.Integer(), nullable=False),
        sa.Column("activa", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("id_modificada_por", sa.UUID(), nullable=True),
        sa.Column(
            "fecha_creacion", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "fecha_actualizacion", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint("tipo_valor = 'INTEGER'", name="ck_politica_seguridad_tipo_valor"),
        sa.CheckConstraint("valor_entero >= 0", name="ck_politica_seguridad_valor_no_negativo"),
        sa.CheckConstraint("version >= 1", name="ck_politica_seguridad_version_positiva"),
        sa.ForeignKeyConstraint(
            ["id_modificada_por"], ["usuario.id_usuario"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id_politica"),
        sa.UniqueConstraint("codigo"),
    )
    _seed_policies()
    _sync_policy_permissions()


def downgrade() -> None:
    raise RuntimeError(
        "Downgrade is disabled because it would discard versioned security-policy history. "
        "Restore a verified database backup instead."
    )
