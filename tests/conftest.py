import os
import secrets

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.pool import StaticPool


# Pytest injects an isolated value before importing application settings.
os.environ["JWT_SECRET_KEY"] = secrets.token_urlsafe(48)
if os.getenv("CU06_TEST_POSTGRES") != "1":
    os.environ["DATABASE_URL"] = "sqlite://"

from app.core import database
from app.core.database import Base
from app.core.seed import seed_database
from app.models import auth, mfa, vault  # noqa: F401


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
    Base.metadata.drop_all(test_engine)
    Base.metadata.create_all(test_engine)
    seed_database()
    try:
        yield
    finally:
        Base.metadata.drop_all(test_engine)
