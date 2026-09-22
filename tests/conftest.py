import base64
import os
import secrets

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.pool import StaticPool


# Pytest injects an isolated value before importing application settings.
os.environ["JWT_SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["TOTP_ENCRYPTION_KEY"] = base64.urlsafe_b64encode(
    secrets.token_bytes(32)
).decode("ascii")
os.environ["SEED_DEMO_ACCOUNTS"] = "1"
os.environ["SEED_ADMIN_NAME"] = "Administrador de Pruebas"
os.environ["SEED_ADMIN_EMAIL"] = "admin@boveda.com"
os.environ["SEED_ADMIN_PASSWORD"] = "Admin1234!*"
os.environ["SEED_MEMBER_NAME"] = "Miembro de Pruebas"
os.environ["SEED_MEMBER_EMAIL"] = "investigador@boveda.com"
os.environ["SEED_MEMBER_PASSWORD"] = "User1234!*"
os.environ["SESSION_COOKIE_SECURE"] = "true"
if os.getenv("CU06_TEST_POSTGRES") != "1":
    os.environ["DATABASE_URL"] = "sqlite://"

from app.core import database
from app.core.database import Base
from app.core.seed import seed_database
from app.models import anomaly, auth, compliance_report, mfa, policy, vault  # noqa: F401
from app.models.policy import PoliticaSeguridad
from app.services.mfa_service import mfa_login_rate_limiter


@compiles(UUID, "sqlite")
def _compile_uuid_as_text(_type, _compiler, **_kwargs):
    # SQLite's NUMERIC affinity can coerce hexadecimal UUIDs to infinity.
    return "CHAR(36)"


test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@event.listens_for(test_engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
    dbapi_connection.execute("PRAGMA foreign_keys=ON")


# Keep the original factory object so tests that imported SessionLocal still use it.
database.engine = test_engine
database.SessionLocal.configure(bind=test_engine)


def _seed_test_policies():
    db = database.SessionLocal()
    try:
        defaults = [
            {"codigo": "INACTIVITY_TIMEOUT_MINUTES", "nombre": "Tiempo de Inactividad para Bloqueo (CU-12)", "valor": "15", "descripcion": "Minutos de inactividad...", "activa": True},
            {"codigo": "MAX_FAILED_LOGIN_ATTEMPTS", "nombre": "Intentos Fallidos de Inicio de Sesión", "valor": "5", "descripcion": "Número máximo de intentos...", "activa": True},
            {"codigo": "LOCKOUT_DURATION_MINUTES", "nombre": "Duración de Bloqueo de Cuenta", "valor": "15", "descripcion": "Duración en minutos...", "activa": True},
            {"codigo": "VAULT_SESSION_DURATION_MINUTES", "nombre": "Duración de Sesión de Bóvedas", "valor": "15", "descripcion": "Vigencia en minutos...", "activa": True},
            {"codigo": "AUDIT_RETENTION_DAYS", "nombre": "Retención de Auditoría Inmutable", "valor": "90", "descripcion": "Días mínimos de retención...", "activa": True},
            {"codigo": "PASSWORD_MIN_LENGTH", "nombre": "Longitud Mínima de Contraseña", "valor": "12", "descripcion": "Longitud mínima de caracteres...", "activa": True},
        ]
        import uuid
        for item in defaults:
            db.add(PoliticaSeguridad(id_politica=uuid.uuid4(), **item))
        db.commit()
    finally:
        db.close()


@pytest.fixture(autouse=True)
def isolated_database():
    Base.metadata.drop_all(test_engine)
    Base.metadata.create_all(test_engine)
    seed_database()
    _seed_test_policies()
    mfa_login_rate_limiter._attempts.clear()
    try:
        yield
    finally:
        Base.metadata.drop_all(test_engine)
