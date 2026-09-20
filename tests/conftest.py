import base64
import os
import re
import secrets

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.engine import make_url
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
if os.getenv("CU06_TEST_POSTGRES") != "1":
    os.environ["DATABASE_URL"] = "sqlite://"


def _assert_disposable_postgres_target() -> None:
    if os.getenv("BOVEDA_L2B_DISPOSABLE_DATABASE") != "1":
        raise RuntimeError("BOVEDA_L2B_DISPOSABLE_DATABASE=1 is required for PostgreSQL tests.")
    try:
        url = make_url(os.environ["DATABASE_URL"])
    except KeyError as error:
        raise RuntimeError("DATABASE_URL is required for PostgreSQL tests.") from error
    if (
        not url.drivername.startswith("postgresql")
        or (url.host or "").lower() not in {"localhost", "127.0.0.1", "::1"}
        or not url.database
        or not re.match(r"^boveda_lote2b_(tmp|temp|test)(?:[_-].+)?$", url.database.lower())
        or url.query
    ):
        raise RuntimeError("PostgreSQL tests require a local disposable boveda_lote2b_* database.")

from app.core import database
from app.core.database import Base
from app.core.seed import seed_database
from app.models import auth, mfa, vault  # noqa: F401
from app.services.mfa_service import mfa_login_rate_limiter


@compiles(UUID, "sqlite")
def _compile_uuid_as_text(_type, _compiler, **_kwargs):
    # SQLite's NUMERIC affinity can coerce hexadecimal UUIDs to infinity.
    return "CHAR(36)"


if os.getenv("CU06_TEST_POSTGRES") == "1":
    _assert_disposable_postgres_target()
    test_engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
else:
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


@pytest.fixture(autouse=True)
def isolated_database():
    if test_engine.dialect.name == "postgresql":
        # The PostgreSQL-only suite is pointed at a disposable database. Resetting the
        # schema avoids dependency cycles among the terminal identity foreign keys.
        with test_engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    else:
        Base.metadata.drop_all(test_engine)
    Base.metadata.create_all(test_engine)
    seed_database()
    mfa_login_rate_limiter._attempts.clear()
    try:
        yield
    finally:
        if test_engine.dialect.name == "postgresql":
            with test_engine.begin() as connection:
                connection.execute(text("DROP SCHEMA public CASCADE"))
                connection.execute(text("CREATE SCHEMA public"))
        else:
            Base.metadata.drop_all(test_engine)
