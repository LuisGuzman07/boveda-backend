from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routes.recovery import get_recovery_service
from app.core.database import Base, get_db
from app.core.security import get_password_hash, hash_token, verify_password
from app.main import app
from app.models.auth import EventoAuditoria, Sesion, Usuario
from app.models.mfa import RecuperacionCuenta
from app.services.recovery_service import RecoveryRateLimiter, RecoveryService


class FakeRecoveryEmail:
    def __init__(self, delivered: bool = True):
        self.delivered = delivered
        self.messages: list[dict[str, str | int]] = []

    def __call__(self, to_email: str, reset_token: str, expires_in_minutes: int) -> bool:
        if self.delivered:
            self.messages.append(
                {
                    "to_email": to_email,
                    "reset_token": reset_token,
                    "expires_in_minutes": expires_in_minutes,
                }
            )
        return self.delivered


@pytest.fixture
def recovery_environment():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    db = Session(engine)
    user = Usuario(
        nombre="Usuario Recuperacion",
        correo="recovery@example.com",
        password_hash=get_password_hash("PasswordBase123!*"),
        estado="ACTIVO",
    )
    db.add(user)
    db.commit()

    mailer = FakeRecoveryEmail()
    limiter = RecoveryRateLimiter()
    previous_overrides = dict(app.dependency_overrides)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_recovery_service] = lambda: RecoveryService(
        db, email_sender=mailer, rate_limiter=limiter
    )
    client = TestClient(app)

    try:
        yield {
            "client": client,
            "db": db,
            "user": user,
            "mailer": mailer,
            "limiter": limiter,
        }
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous_overrides)
        db.close()
        engine.dispose()


def _request_recovery(environment, email="recovery@example.com"):
    return environment["client"].post(
        "/api/v1/auth/recovery/forgot-password", json={"correo": email}
    )


def _captured_token(environment) -> str:
    return environment["mailer"].messages[-1]["reset_token"]


def test_forgot_password_is_generic_and_never_returns_a_token(recovery_environment):
    existing = _request_recovery(recovery_environment)
    missing = _request_recovery(recovery_environment, "missing@example.com")

    assert existing.status_code == missing.status_code == 200
    assert existing.json() == missing.json()
    assert set(existing.json()) == {"status", "message"}
    assert len(recovery_environment["mailer"].messages) == 1

    raw_token = _captured_token(recovery_environment)
    record = recovery_environment["db"].scalar(
        select(RecuperacionCuenta).where(RecuperacionCuenta.tipo == "RESET_TOKEN")
    )
    assert record is not None
    assert record.token_hash == hash_token(raw_token)
    assert raw_token not in record.codigo
    assert raw_token not in str(existing.json())

    audit_details = recovery_environment["db"].scalars(select(EventoAuditoria)).all()
    assert all(raw_token not in str(event.detalles) for event in audit_details)


def test_smtp_unavailable_invalidates_the_generated_token_without_http_exposure(
    recovery_environment,
):
    recovery_environment["mailer"].delivered = False

    response = _request_recovery(recovery_environment)

    assert response.status_code == 200
    assert set(response.json()) == {"status", "message"}
    assert recovery_environment["mailer"].messages == []
    record = recovery_environment["db"].scalar(
        select(RecuperacionCuenta).where(RecuperacionCuenta.tipo == "RESET_TOKEN")
    )
    assert record is not None
    assert record.utilizado is True


def test_validate_token_uses_post_and_does_not_disclose_email(recovery_environment):
    _request_recovery(recovery_environment)
    token = _captured_token(recovery_environment)

    valid = recovery_environment["client"].post(
        "/api/v1/auth/recovery/validate-token", json={"token": token}
    )
    invalid = recovery_environment["client"].post(
        "/api/v1/auth/recovery/validate-token", json={"token": "invalid-token-1234567890"}
    )

    assert valid.status_code == invalid.status_code == 200
    assert valid.json()["valid"] is True
    assert invalid.json()["valid"] is False
    assert "correo" not in valid.json()


def test_expired_token_is_rejected(recovery_environment):
    _request_recovery(recovery_environment)
    token = _captured_token(recovery_environment)
    record = recovery_environment["db"].scalar(
        select(RecuperacionCuenta).where(RecuperacionCuenta.tipo == "RESET_TOKEN")
    )
    record.fecha_expiracion = datetime.now(timezone.utc) - timedelta(minutes=1)
    recovery_environment["db"].commit()

    validation = recovery_environment["client"].post(
        "/api/v1/auth/recovery/validate-token", json={"token": token}
    )
    reset = recovery_environment["client"].post(
        "/api/v1/auth/recovery/reset-password",
        json={"token": token, "password": "NuevaPassword123!*"},
    )

    assert validation.json()["valid"] is False
    assert reset.status_code == 400


def test_reset_consumes_token_revokes_sessions_and_changes_password(recovery_environment):
    _request_recovery(recovery_environment)
    token = _captured_token(recovery_environment)
    session = Sesion(
        id_usuario=recovery_environment["user"].id_usuario,
        refresh_token_hash="test-session-hash",
        fecha_expiracion=datetime.now(timezone.utc) + timedelta(days=1),
        revocada=False,
    )
    recovery_environment["db"].add(session)
    recovery_environment["db"].commit()

    payload = {"token": token, "password": "NuevaPassword123!*"}
    reset = recovery_environment["client"].post(
        "/api/v1/auth/recovery/reset-password", json=payload
    )
    reused = recovery_environment["client"].post(
        "/api/v1/auth/recovery/reset-password", json=payload
    )

    recovery_environment["db"].expire_all()
    user = recovery_environment["db"].get(Usuario, recovery_environment["user"].id_usuario)
    token_record = recovery_environment["db"].scalar(
        select(RecuperacionCuenta).where(RecuperacionCuenta.token_hash == hash_token(token))
    )
    updated_session = recovery_environment["db"].get(Sesion, session.id_sesion)

    assert reset.status_code == 200
    assert reset.json()["sesiones_revocadas"] == 1
    assert verify_password("NuevaPassword123!*", user.password_hash)
    assert token_record.utilizado is True
    assert updated_session.revocada is True
    assert reused.status_code == 400


def test_new_request_invalidates_the_previous_token(recovery_environment):
    _request_recovery(recovery_environment)
    first_token = _captured_token(recovery_environment)
    _request_recovery(recovery_environment)
    second_token = _captured_token(recovery_environment)

    first_validation = recovery_environment["client"].post(
        "/api/v1/auth/recovery/validate-token", json={"token": first_token}
    )
    second_validation = recovery_environment["client"].post(
        "/api/v1/auth/recovery/validate-token", json={"token": second_token}
    )

    assert first_validation.json()["valid"] is False
    assert second_validation.json()["valid"] is True


def test_rate_limit_stops_repeated_delivery_without_changing_the_response(
    recovery_environment,
):
    recovery_environment["limiter"].max_attempts = 1

    first = _request_recovery(recovery_environment)
    second = _request_recovery(recovery_environment)

    assert first.json() == second.json()
    assert len(recovery_environment["mailer"].messages) == 1


def test_rate_limit_does_not_trust_spoofed_forwarded_for(recovery_environment):
    recovery_environment["limiter"].max_attempts = 1
    client = recovery_environment["client"]

    first = client.post(
        "/api/v1/auth/recovery/forgot-password",
        json={"correo": "recovery@example.com"},
        headers={"X-Forwarded-For": "198.51.100.10"},
    )
    second = client.post(
        "/api/v1/auth/recovery/forgot-password",
        json={"correo": "recovery@example.com"},
        headers={"X-Forwarded-For": "203.0.113.20"},
    )

    assert first.json() == second.json()
    assert len(recovery_environment["mailer"].messages) == 1
