import uuid
from fastapi.testclient import TestClient
from sqlalchemy import select
from app.core.database import SessionLocal
from app.main import app
from app.models.auth import EventoAuditoria, Sesion, Usuario

client = TestClient(app)


def test_register_user_success():
    unique_email = f"nuevo_investigador_{uuid.uuid4().hex[:8]}@boveda.com"
    payload = {
        "nombre": "Dra. Maria Perez",
        "correo": unique_email,
        "password": "PasswordFuerte123!*",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["nombre"] == "Dra. Maria Perez"
    assert data["correo"] == unique_email
    assert data["estado"] == "ACTIVO"
    assert data["correo_verificado"] is False
    assert len(data["roles"]) > 0
    assert any(r["nombre"] == "Miembro" for r in data["roles"])

    # Verificar que se creó el evento de auditoría
    db = SessionLocal()
    try:
        user_stmt = select(Usuario).where(Usuario.correo == unique_email)
        user = db.scalars(user_stmt).first()
        assert user is not None

        audit_stmt = select(EventoAuditoria).where(
            EventoAuditoria.id_usuario == user.id_usuario,
            EventoAuditoria.accion == "REGISTRO_USUARIO",
        )
        audit_event = db.scalars(audit_stmt).first()
        assert audit_event is not None
        assert audit_event.resultado == "EXITO"
    finally:
        db.close()


def test_register_duplicate_email():
    payload = {
        "nombre": "Admin Duplicado",
        "correo": "admin@boveda.com",
        "password": "PasswordFuerte123!*",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 409
    assert "Ya existe una cuenta" in response.json()["detail"]


def test_register_weak_password():
    payload = {
        "nombre": "Usuario Clave Debil",
        "correo": f"test_{uuid.uuid4().hex[:8]}@boveda.com",
        "password": "simplepassword",  # Falta mayúscula, número y carácter especial
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422


def test_login_success():
    payload = {
        "correo": "admin@boveda.com",
        "password": "Admin1234!*",
        "dispositivo": {
            "nombre": "Pytest Test Runner",
            "tipo": "DESKTOP",
            "sistema_operativo": "Linux/Docker",
            "identificador_seguro": "pytest-device-id-001",
        },
    }
    response = client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["usuario"]["correo"] == "admin@boveda.com"
    assert "Administrador" in data["roles"]
    assert len(data["permisos"]) > 0

    # Verificar que se creó la sesión en la base de datos
    db = SessionLocal()
    try:
        user_stmt = select(Usuario).where(Usuario.correo == "admin@boveda.com")
        user = db.scalars(user_stmt).first()
        assert user is not None

        session_stmt = select(Sesion).where(
            Sesion.id_usuario == user.id_usuario,
            Sesion.revocada == False,
        )
        session = db.scalars(session_stmt).first()
        assert session is not None

        # Verificar evento de auditoría
        audit_stmt = select(EventoAuditoria).where(
            EventoAuditoria.id_usuario == user.id_usuario,
            EventoAuditoria.accion == "LOGIN_EXITOSO",
        )
        audit_event = db.scalars(audit_stmt).first()
        assert audit_event is not None
        assert audit_event.resultado == "EXITO"
    finally:
        db.close()


def test_login_wrong_password():
    payload = {
        "correo": "admin@boveda.com",
        "password": "PasswordIncorrecta123!",
        "dispositivo": {
            "nombre": "Pytest Client",
            "tipo": "DESKTOP",
            "identificador_seguro": "pytest-device-id-002",
        },
    }
    response = client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 401
    assert "Credenciales inválidas" in response.json()["detail"]


def test_get_me_and_refresh_and_logout():
    # 1. Login
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "correo": "investigador@boveda.com",
            "password": "User1234!*",
            "dispositivo": {
                "nombre": "Investigador Workstation",
                "tipo": "DESKTOP",
                "identificador_seguro": "inv-device-001",
            },
        },
    )
    assert login_res.status_code == 200
    auth_data = login_res.json()
    access_token = auth_data["access_token"]
    refresh_token = auth_data["refresh_token"]

    # 2. Probar /me con Bearer token
    me_res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_res.status_code == 200
    assert me_res.json()["correo"] == "investigador@boveda.com"
    assert me_res.json()["nombre"] == "Dr. Luis Guzmán"

    # 3. Probar /refresh
    refresh_res = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_res.status_code == 200
    assert "access_token" in refresh_res.json()
    new_access_token = refresh_res.json()["access_token"]

    # 4. Probar /logout
    logout_res = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {new_access_token}"},
        json={"refresh_token": refresh_token},
    )
    assert logout_res.status_code == 200
    assert logout_res.json()["status"] == "ok"
