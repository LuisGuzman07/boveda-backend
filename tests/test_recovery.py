from unittest.mock import patch
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from app.core.database import SessionLocal
from app.main import app
from app.models.auth import EventoAuditoria, Sesion, Usuario
from app.models.mfa import RecuperacionCuenta

client = TestClient(app)

TEST_USER_EMAIL = f"test_rec_{uuid.uuid4().hex[:8]}@boveda.com"
TEST_USER_PASSWORD = "PasswordBase123!*"


@pytest.fixture(autouse=True)
def mock_email_simulation_for_tests():
    """Aisla las pruebas automáticas para usar el modo simulación y no saturar el servidor SMTP de Gmail."""
    with patch("app.services.recovery_service.send_recovery_email", return_value=False):
        yield


@pytest.fixture(scope="module", autouse=True)
def setup_test_user():
    """Crea un usuario dedicado para las pruebas de recuperación sin alterar cuentas existentes."""
    reg_res = client.post(
        "/api/v1/auth/register",
        json={
            "nombre": "Usuario Prueba Recuperacion",
            "correo": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD,
        },
    )
    assert reg_res.status_code == 201



def test_forgot_password_success():
    res = client.post(
        "/api/v1/auth/recovery/forgot-password",
        json={"correo": TEST_USER_EMAIL},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["simulation_token"] is not None
    assert "token=" in data["simulation_reset_url"]

    # Verificar registro en base de datos
    db = SessionLocal()
    try:
        user = db.scalars(select(Usuario).where(Usuario.correo == TEST_USER_EMAIL)).first()
        assert user is not None

        token_rec = db.scalars(
            select(RecuperacionCuenta).where(
                RecuperacionCuenta.id_usuario == user.id_usuario,
                RecuperacionCuenta.tipo == "RESET_TOKEN",
                RecuperacionCuenta.utilizado == False,
            )
        ).first()
        assert token_rec is not None
        assert token_rec.codigo.startswith("RST-")

        # Verificar auditoría
        audit = db.scalars(
            select(EventoAuditoria).where(
                EventoAuditoria.id_usuario == user.id_usuario,
                EventoAuditoria.accion == "SOLICITUD_RECUPERACION",
            )
        ).first()
        assert audit is not None
        assert audit.resultado == "EXITO"
    finally:
        db.close()


def test_forgot_password_nonexistent_user():
    fake_email = f"fantasma_{uuid.uuid4().hex[:8]}@boveda.com"
    res = client.post(
        "/api/v1/auth/recovery/forgot-password",
        json={"correo": fake_email},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    # No debe generar token de simulación para correo inexistente
    assert data.get("simulation_token") is None

    # Verificar auditoría de intento fallido
    db = SessionLocal()
    try:
        audit = db.scalars(
            select(EventoAuditoria).where(
                EventoAuditoria.accion == "SOLICITUD_RECUPERACION_FALLIDA",
                EventoAuditoria.resultado == "FALLO",
            )
        ).first()
        assert audit is not None
    finally:
        db.close()


def test_validate_token():
    # 1. Generar token
    res = client.post(
        "/api/v1/auth/recovery/forgot-password",
        json={"correo": TEST_USER_EMAIL},
    )
    token = res.json()["simulation_token"]

    # 2. Validar token correcto
    val_res = client.get(f"/api/v1/auth/recovery/validate-token?token={token}")
    assert val_res.status_code == 200
    assert val_res.json()["valid"] is True
    assert val_res.json()["correo"] == TEST_USER_EMAIL

    # 3. Validar token incorrecto
    fake_token = "token_totalmente_invalido_1234567890"
    inv_res = client.get(f"/api/v1/auth/recovery/validate-token?token={fake_token}")
    assert inv_res.status_code == 200
    assert inv_res.json()["valid"] is False


def test_reset_password_weak_password():
    res = client.post(
        "/api/v1/auth/recovery/forgot-password",
        json={"correo": TEST_USER_EMAIL},
    )
    token = res.json()["simulation_token"]

    bad_payload = {
        "token": token,
        "password": "debil",  # No cumple requisitos
    }
    reset_res = client.post("/api/v1/auth/recovery/reset-password", json=bad_payload)
    assert reset_res.status_code == 422


def test_reset_password_same_as_old():
    res = client.post(
        "/api/v1/auth/recovery/forgot-password",
        json={"correo": TEST_USER_EMAIL},
    )
    token = res.json()["simulation_token"]

    same_payload = {
        "token": token,
        "password": TEST_USER_PASSWORD,  # Misma contraseña actual
    }
    reset_res = client.post("/api/v1/auth/recovery/reset-password", json=same_payload)
    assert reset_res.status_code == 400
    assert "no puede ser idéntica" in reset_res.json()["detail"]


def test_reset_password_full_lifecycle_and_session_revocation():
    # 1. Iniciar sesión para tener una sesión activa
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "correo": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD,
            "dispositivo": {
                "nombre": "Laptop de Prueba",
                "tipo": "DESKTOP",
                "identificador_seguro": "test-device-recovery-lifecycle",
            },
        },
    )
    assert login_res.status_code == 200

    # 2. Solicitar restablecimiento
    forgot_res = client.post(
        "/api/v1/auth/recovery/forgot-password",
        json={"correo": TEST_USER_EMAIL},
    )
    token = forgot_res.json()["simulation_token"]

    # 3. Restablecer con nueva contraseña
    new_password = "NuevaPasswordSegura2026!#"
    reset_res = client.post(
        "/api/v1/auth/recovery/reset-password",
        json={
            "token": token,
            "password": new_password,
        },
    )
    assert reset_res.status_code == 200
    data = reset_res.json()
    assert data["status"] == "ok"
    assert data["sesiones_revocadas"] >= 1
    assert "Cero Conocimiento" in data["zero_knowledge_notice"]

    # 4. Probar login con contraseña antigua -> debe fallar (401)
    old_login = client.post(
        "/api/v1/auth/login",
        json={
            "correo": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD,
        },
    )
    assert old_login.status_code == 401

    # 5. Probar login con nueva contraseña -> debe ser exitoso (200)
    new_login = client.post(
        "/api/v1/auth/login",
        json={
            "correo": TEST_USER_EMAIL,
            "password": new_password,
        },
    )
    assert new_login.status_code == 200

    # 6. Intentar reutilizar el token -> debe fallar (400)
    reuse_res = client.post(
        "/api/v1/auth/recovery/reset-password",
        json={
            "token": token,
            "password": "OtraPassword2026!#",
        },
    )
    assert reuse_res.status_code == 400
