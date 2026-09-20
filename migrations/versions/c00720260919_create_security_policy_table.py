"""CU-17: Crear tabla politica_seguridad y sembrar políticas globales."""
import uuid
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "c00720260919"
down_revision = "c00620260917"
branch_labels = None
depends_on = None

DEFAULT_POLICIES = [
    {
        "id_politica": uuid.UUID("11111111-1111-1111-1111-111111111101"),
        "codigo": "INACTIVITY_TIMEOUT_MINUTES",
        "nombre": "Tiempo de Inactividad para Bloqueo (CU-12)",
        "valor": "15",
        "descripcion": "Minutos de inactividad del usuario antes de purgar las claves criptográficas de memoria RAM y bloquear la terminal.",
        "activa": True,
    },
    {
        "id_politica": uuid.UUID("11111111-1111-1111-1111-111111111102"),
        "codigo": "MAX_FAILED_LOGIN_ATTEMPTS",
        "nombre": "Intentos Fallidos de Inicio de Sesión",
        "valor": "5",
        "descripcion": "Número máximo de intentos consecutivos fallidos de contraseña antes de bloquear la cuenta.",
        "activa": True,
    },
    {
        "id_politica": uuid.UUID("11111111-1111-1111-1111-111111111103"),
        "codigo": "LOCKOUT_DURATION_MINUTES",
        "nombre": "Duración de Bloqueo de Cuenta",
        "valor": "15",
        "descripcion": "Duración en minutos durante los cuales la cuenta permanece bloqueada tras exceder el umbral de intentos fallidos.",
        "activa": True,
    },
    {
        "id_politica": uuid.UUID("11111111-1111-1111-1111-111111111104"),
        "codigo": "VAULT_SESSION_DURATION_MINUTES",
        "nombre": "Duración de Sesión de Bóvedas",
        "valor": "15",
        "descripcion": "Vigencia en minutos del token de acceso a bóvedas firmado con hardware local y protegido por TOTP.",
        "activa": True,
    },
    {
        "id_politica": uuid.UUID("11111111-1111-1111-1111-111111111105"),
        "codigo": "AUDIT_RETENTION_DAYS",
        "nombre": "Retención de Auditoría Inmutable",
        "valor": "90",
        "descripcion": "Días mínimos de retención obligatoria para eventos de auditoría y trazabilidad inmutable.",
        "activa": True,
    },
    {
        "id_politica": uuid.UUID("11111111-1111-1111-1111-111111111106"),
        "codigo": "PASSWORD_MIN_LENGTH",
        "nombre": "Longitud Mínima de Contraseña",
        "valor": "12",
        "descripcion": "Longitud mínima de caracteres requerida para contraseñas de usuario y frases de paso de bóvedas.",
        "activa": True,
    },
]


def upgrade():
    table = op.create_table(
        "politica_seguridad",
        sa.Column("id_politica", UUID(as_uuid=True), primary_key=True),
        sa.Column("codigo", sa.String(50), nullable=False),
        sa.Column("nombre", sa.String(100), nullable=False),
        sa.Column("valor", sa.String(255), nullable=False),
        sa.Column("descripcion", sa.Text(), nullable=True),
        sa.Column("activa", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("modificada_por", UUID(as_uuid=True), sa.ForeignKey("usuario.id_usuario", ondelete="SET NULL"), nullable=True),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("fecha_actualizacion", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_politica_seguridad_codigo", "politica_seguridad", ["codigo"], unique=True)

    # Seed default policies
    op.bulk_insert(table, DEFAULT_POLICIES)


def downgrade():
    op.drop_index("ix_politica_seguridad_codigo", table_name="politica_seguridad")
    op.drop_table("politica_seguridad")
