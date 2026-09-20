import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select
from app.core.database import SessionLocal
from app.main import app
from app.models.auth import EventoAuditoria, Sesion, Usuario
from app.core.config import settings

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


def test_expired_temporary_lock_allows_login_again():
    db = SessionLocal()
    try:
        user = db.scalars(select(Usuario).where(Usuario.correo == "admin@boveda.com")).first()
        assert user is not None
        user.estado = "BLOQUEADO"
        user.intentos_fallidos = settings.MAX_FAILED_LOGIN_ATTEMPTS
        user.bloqueado_hasta = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()

    response = client.post(
        "/api/v1/auth/login",
        json={
            "correo": "admin@boveda.com",
            "password": "Admin1234!*",
            "dispositivo": {"identificador_seguro": "expired-lock-device", "tipo": "WEB"},
        },
    )

    assert response.status_code == 200


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
    assert me_res.json()["nombre"] == "Miembro de Pruebas"

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


def test_refresh_rotation_reuse_revokes_the_session_family():
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "correo": "admin@boveda.com",
            "password": "Admin1234!*",
            "dispositivo": {
                "identificador_seguro": f"refresh-{uuid.uuid4()}",
                "tipo": "WEB",
            },
        },
    )
    original_refresh = login_res.json()["refresh_token"]
    rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": original_refresh})
    assert rotated.status_code == 200
    fresh_access = rotated.json()["access_token"]
    assert rotated.json()["refresh_token"] != original_refresh

    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": original_refresh})
    assert replay.status_code == 401
    assert client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {fresh_access}"}
    ).status_code == 401


def test_web_session_uses_http_only_cookie_and_csrf():
    web_client = TestClient(app, base_url="https://testserver")
    response = web_client.post(
        "/api/v1/auth/web/login",
        json={"correo": "admin@boveda.com", "password": "Admin1234!*"},
    )
    assert response.status_code == 200
    assert response.json()["refresh_token"] is None
    set_cookie = "\n".join(response.headers.get_list("set-cookie"))
    assert settings.SESSION_COOKIE_NAME in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    csrf_set_cookie = next(
        cookie
        for cookie in response.headers.get_list("set-cookie")
        if cookie.startswith(f"{settings.CSRF_COOKIE_NAME}=")
    )
    assert "Path=/" in csrf_set_cookie
    assert "HttpOnly" not in csrf_set_cookie

    rejected = web_client.post("/api/v1/auth/web/refresh")
    assert rejected.status_code == 403
    csrf = web_client.cookies.get(settings.CSRF_COOKIE_NAME)
    refreshed = web_client.post(
        "/api/v1/auth/web/refresh", headers={"X-CSRF-Token": csrf}
    )
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"]
