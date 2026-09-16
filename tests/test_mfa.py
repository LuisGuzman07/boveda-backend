import uuid
import pyotp
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_mfa_full_lifecycle():
    email = f"mfa_test_{uuid.uuid4().hex[:8]}@boveda.com"
    password = "MfaPassword123!*"

    # 1. Registrar usuario único de prueba
    reg_res = client.post(
        "/api/v1/auth/register",
        json={"nombre": "Usuario Prueba MFA", "correo": email, "password": password},
    )
    assert reg_res.status_code == 201

    # 2. Login para obtener token
    login_res = client.post(
        "/api/v1/auth/login",
        json={"correo": email, "password": password},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Consultar estado de MFA (inicialmente deshabilitado)
    status_res = client.get("/api/v1/auth/mfa/status", headers=headers)
    assert status_res.status_code == 200
    assert status_res.json()["enabled"] is False

    # 4. Iniciar Setup de MFA
    setup_res = client.post("/api/v1/auth/mfa/setup", headers=headers)
    assert setup_res.status_code == 200
    setup_data = setup_res.json()
    assert "secret" in setup_data
    assert "qr_code_base64" in setup_data
    assert len(setup_data["backup_codes"]) == 8
    secret = setup_data["secret"]

    # 5. Activar MFA enviando el código TOTP generado
    totp = pyotp.TOTP(secret)
    current_code = totp.now()

    enable_res = client.post(
        "/api/v1/auth/mfa/enable",
        headers=headers,
        json={"code": current_code},
    )
    assert enable_res.status_code == 200
    assert enable_res.json()["status"] == "ok"

    # 6. Verificar que el estado ahora sea ACTIVO
    status_active_res = client.get("/api/v1/auth/mfa/status", headers=headers)
    assert status_active_res.status_code == 200
    assert status_active_res.json()["enabled"] is True

    # 7. Probar Login con MFA requerido
    login_mfa_step1 = client.post(
        "/api/v1/auth/login",
        json={"correo": email, "password": password},
    )
    assert login_mfa_step1.status_code == 200
    mfa_response = login_mfa_step1.json()
    assert mfa_response["mfa_required"] is True
    assert "mfa_token" in mfa_response
    mfa_token = mfa_response["mfa_token"]

    # 8. Completar Login enviando el código 2FA
    verify_mfa_res = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": mfa_token, "code": totp.now()},
    )
    assert verify_mfa_res.status_code == 200
    final_auth = verify_mfa_res.json()
    assert "access_token" in final_auth
    assert final_auth["usuario"]["correo"] == email

    # 9. Desactivar MFA para dejar el usuario limpio
    disable_res = client.post(
        "/api/v1/auth/mfa/disable",
        headers={"Authorization": f"Bearer {final_auth['access_token']}"},
        json={"password": password},
    )
    assert disable_res.status_code == 200
    assert disable_res.json()["status"] == "ok"

    # 10. Verificar estado deshabilitado
    status_final_res = client.get(
        "/api/v1/auth/mfa/status",
        headers={"Authorization": f"Bearer {final_auth['access_token']}"},
    )
    assert status_final_res.json()["enabled"] is False
