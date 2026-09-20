"""Enforce device-bound sessions and device identity proof.

Revision ID: d2b20260919
Revises: f2a1b3c4d5e6
"""

import uuid

from alembic import context, op
import sqlalchemy as sa


revision = "d2b20260919"
down_revision = "f2a1b3c4d5e6"
branch_labels = None
depends_on = None


def _backfill_sessions() -> None:
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id_sesion FROM sesion")).mappings()
    for row in rows:
        bind.execute(
            sa.text(
                """
                UPDATE sesion
                SET familia_refresh_id = :family_id,
                    refresh_jti = :refresh_jti,
                    revocada = TRUE,
                    motivo_revocacion = COALESCE(motivo_revocacion, 'MIGRACION_SESION_NO_VINCULADA')
                WHERE id_sesion = :session_id
                """
            ),
            {
                "family_id": str(uuid.uuid4()),
                "refresh_jti": f"legacy-{row['id_sesion']}",
                "session_id": row["id_sesion"],
            },
        )


def _assert_unique_installations() -> None:
    bind = op.get_bind()
    duplicate = bind.execute(
        sa.text(
            """
            SELECT id_usuario, identificador_seguro
            FROM dispositivo
            GROUP BY id_usuario, identificador_seguro
            HAVING COUNT(*) > 1
            LIMIT 1
            """
        )
    ).first()
    if duplicate:
        raise RuntimeError(
            "La migracion requiere identificadores de dispositivo unicos por usuario. "
            "Resuelve los duplicados antes de reintentarla."
        )


def upgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "This migration backfills and revokes legacy sessions, so it must run online."
        )

    op.add_column("dispositivo", sa.Column("clave_firma_boveda", sa.Text(), nullable=True))
    op.add_column("dispositivo", sa.Column("algoritmo_clave", sa.String(length=50), nullable=True))
    op.add_column(
        "dispositivo", sa.Column("huella_clave_publica", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "dispositivo", sa.Column("identidad_verificada_en", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "dispositivo", sa.Column("confianza_otorgada_en", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index(
        "ix_dispositivo_huella_clave_publica", "dispositivo", ["huella_clave_publica"]
    )
    _assert_unique_installations()
    op.execute(
        """
        UPDATE dispositivo
        SET clave_firma_boveda = public_key,
            public_key = NULL,
            algoritmo_clave = NULL,
            huella_clave_publica = NULL,
            identidad_verificada_en = NULL,
            confianza_otorgada_en = NULL,
            estado = CASE
            WHEN estado IN ('REVOCADO', 'REVOKED') THEN 'REVOKED'
            ELSE 'PENDING'
        END,
        es_confiable = FALSE
        """
    )
    op.create_unique_constraint(
        "uq_dispositivo_usuario_identificador",
        "dispositivo",
        ["id_usuario", "identificador_seguro"],
    )

    op.add_column("sesion", sa.Column("familia_refresh_id", sa.UUID(), nullable=True))
    op.add_column("sesion", sa.Column("refresh_jti", sa.String(length=64), nullable=True))
    op.add_column(
        "sesion",
        sa.Column("tipo_cliente", sa.String(length=20), server_default=sa.text("'NATIVE'"), nullable=False),
    )
    op.add_column("sesion", sa.Column("csrf_hash", sa.String(length=64), nullable=True))
    op.add_column(
        "sesion", sa.Column("refresh_consumido_en", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "sesion", sa.Column("mfa_verificado_en", sa.DateTime(timezone=True), nullable=True)
    )
    _backfill_sessions()
    op.alter_column("sesion", "familia_refresh_id", nullable=False)
    op.alter_column("sesion", "refresh_jti", nullable=False)
    op.create_index("ix_sesion_familia_refresh_id", "sesion", ["familia_refresh_id"])
    op.create_index("ix_sesion_refresh_jti", "sesion", ["refresh_jti"])

    op.create_table(
        "desafio_dispositivo",
        sa.Column("id_desafio", sa.UUID(), nullable=False),
        sa.Column("id_usuario", sa.UUID(), nullable=False),
        sa.Column("id_dispositivo", sa.UUID(), nullable=False),
        sa.Column("id_sesion", sa.UUID(), nullable=False),
        sa.Column("proposito", sa.String(length=50), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("context_hash", sa.String(length=64), nullable=False),
        sa.Column("fecha_expiracion", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumido_en", sa.DateTime(timezone=True), nullable=True),
        sa.Column("intentos", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["id_dispositivo"], ["dispositivo.id_dispositivo"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["id_sesion"], ["sesion.id_sesion"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["id_usuario"], ["usuario.id_usuario"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id_desafio"),
    )
    op.create_index("ix_desafio_dispositivo_id_usuario", "desafio_dispositivo", ["id_usuario"])
    op.create_index("ix_desafio_dispositivo_id_dispositivo", "desafio_dispositivo", ["id_dispositivo"])
    op.create_index("ix_desafio_dispositivo_id_sesion", "desafio_dispositivo", ["id_sesion"])

    op.create_table(
        "sesion_boveda",
        sa.Column("id_sesion_boveda", sa.UUID(), nullable=False),
        sa.Column("id_usuario", sa.UUID(), nullable=False),
        sa.Column("id_dispositivo", sa.UUID(), nullable=False),
        sa.Column("id_sesion", sa.UUID(), nullable=False),
        sa.Column("id_desafio", sa.UUID(), nullable=False),
        sa.Column("jti", sa.String(length=64), nullable=False),
        sa.Column("mfa_verificado_en", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fecha_expiracion", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revocada", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("motivo_revocacion", sa.String(length=255), nullable=True),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["id_desafio"], ["desafio_dispositivo.id_desafio"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["id_dispositivo"], ["dispositivo.id_dispositivo"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["id_sesion"], ["sesion.id_sesion"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["id_usuario"], ["usuario.id_usuario"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id_sesion_boveda"),
        sa.UniqueConstraint("id_desafio"),
        sa.UniqueConstraint("jti"),
    )
    op.create_index("ix_sesion_boveda_id_usuario", "sesion_boveda", ["id_usuario"])
    op.create_index("ix_sesion_boveda_id_dispositivo", "sesion_boveda", ["id_dispositivo"])
    op.create_index("ix_sesion_boveda_id_sesion", "sesion_boveda", ["id_sesion"])


def downgrade() -> None:
    raise RuntimeError(
        "Downgrade is disabled because it would discard device proof and session provenance. "
        "Restore a database backup instead."
    )
