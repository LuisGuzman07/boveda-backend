import uuid
import pyotp
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.core.database import SessionLocal
from app.main import app
from app.models.auth import Sesion, Usuario
from app.models.mfa import AutenticadorMfa, RecuperacionCuenta
from app.services.mfa_service import MfaService

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

    db = SessionLocal()
    try:
        user = db.scalars(select(Usuario).where(Usuario.correo == email)).first()
        assert user is not None
        assert all(
            item.estado == "REVOCADO"
            for item in db.scalars(
                select(AutenticadorMfa).where(AutenticadorMfa.id_usuario == user.id_usuario)
            )
        )
        assert all(
            item.utilizado
            for item in db.scalars(
                select(RecuperacionCuenta).where(
                    RecuperacionCuenta.id_usuario == user.id_usuario,
                    RecuperacionCuenta.tipo == "BACKUP_CODE",
                )
            )
        )
        assert all(
            item.revocada
            for item in db.scalars(select(Sesion).where(Sesion.id_usuario == user.id_usuario))
        )
    finally:
        db.close()

    # 10. Desactivar MFA revoca la sesión que realizó el cambio.
    stale_status = client.get(
        "/api/v1/auth/mfa/status",
        headers={"Authorization": f"Bearer {final_auth['access_token']}"},
    )
    assert stale_status.status_code == 401

    # 11. Una sesión nueva confirma que no queda MFA activo.
    relogin = client.post(
        "/api/v1/auth/login",
        json={"correo": email, "password": password},
    )
    assert relogin.status_code == 200
    assert relogin.json()["mfa_required"] is False
    status_final_res = client.get(
        "/api/v1/auth/mfa/status",
        headers={"Authorization": f"Bearer {relogin.json()['access_token']}"},
    )
    assert status_final_res.json()["enabled"] is False


def test_replacing_mfa_revokes_existing_sessions_and_old_codes():
    email = f"mfa_replace_{uuid.uuid4().hex[:8]}@boveda.com"
    password = "MfaPassword123!*"
    assert client.post(
        "/api/v1/auth/register",
        json={"nombre": "Usuario Reemplazo MFA", "correo": email, "password": password},
    ).status_code == 201

    initial_login = client.post(
        "/api/v1/auth/login",
        json={"correo": email, "password": password},
    )
    initial_token = initial_login.json()["access_token"]
    initial_setup = client.post(
        "/api/v1/auth/mfa/setup",
        headers={"Authorization": f"Bearer {initial_token}"},
    ).json()
    initial_secret = initial_setup["secret"]
    initial_backup_code = initial_setup["backup_codes"][0]
    assert client.post(
        "/api/v1/auth/mfa/enable",
        headers={"Authorization": f"Bearer {initial_token}"},
        json={"code": pyotp.TOTP(initial_secret).now()},
    ).status_code == 200

    pending = client.post(
        "/api/v1/auth/login",
        json={"correo": email, "password": password},
    ).json()
    verified = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": pending["mfa_token"], "code": pyotp.TOTP(initial_secret).now()},
    )
    assert verified.status_code == 200
    active_token = verified.json()["access_token"]

    # This pending token must not survive a later replacement security boundary.
    stale_pending = client.post(
        "/api/v1/auth/login",
        json={"correo": email, "password": password},
    ).json()

    replacement_setup = client.post(
        "/api/v1/auth/mfa/setup",
        headers={"Authorization": f"Bearer {active_token}"},
    )
    assert replacement_setup.status_code == 200
    replacement_secret = replacement_setup.json()["secret"]
    replacement_backup_code = replacement_setup.json()["backup_codes"][0]

    # Setup returns backup codes for display, but they are unusable until TOTP activation.
    pending_code_login = client.post(
        "/api/v1/auth/login",
        json={"correo": email, "password": password},
    ).json()
    assert client.post(
        "/api/v1/auth/mfa/verify-login",
        json={
            "mfa_token": pending_code_login["mfa_token"],
            "code": replacement_backup_code,
        },
    ).status_code == 401

    replacement = client.post(
        "/api/v1/auth/mfa/enable",
        headers={"Authorization": f"Bearer {active_token}"},
        json={"code": pyotp.TOTP(replacement_secret).now()},
    )
    assert replacement.status_code == 200
    assert client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {active_token}"},
    ).status_code == 401
    assert client.post(
        "/api/v1/auth/mfa/verify-login",
        json={
            "mfa_token": stale_pending["mfa_token"],
            "code": pyotp.TOTP(replacement_secret).now(),
        },
    ).status_code == 401

    old_factor_pending = client.post(
        "/api/v1/auth/login",
        json={"correo": email, "password": password},
    ).json()
    assert client.post(
        "/api/v1/auth/mfa/verify-login",
        json={
            "mfa_token": old_factor_pending["mfa_token"],
            "code": pyotp.TOTP(initial_secret).now(),
        },
    ).status_code == 401

    old_backup_pending = client.post(
        "/api/v1/auth/login",
        json={"correo": email, "password": password},
    ).json()
    assert client.post(
        "/api/v1/auth/mfa/verify-login",
        json={
            "mfa_token": old_backup_pending["mfa_token"],
            "code": initial_backup_code,
        },
    ).status_code == 401

    fresh_pending = client.post(
        "/api/v1/auth/login",
        json={"correo": email, "password": password},
    ).json()
    assert client.post(
        "/api/v1/auth/mfa/verify-login",
        json={
            "mfa_token": fresh_pending["mfa_token"],
            "code": replacement_backup_code,
        },
    ).status_code == 200


def test_mfa_setup_rechecks_a_revoked_session_before_persisting_credentials():
    email = f"mfa_stale_{uuid.uuid4().hex[:8]}@boveda.com"
    password = "MfaPassword123!*"
    assert client.post(
        "/api/v1/auth/register",
        json={"nombre": "Usuario Sesion Revocada", "correo": email, "password": password},
    ).status_code == 201
    assert client.post(
        "/api/v1/auth/login",
        json={"correo": email, "password": password},
    ).status_code == 200

    db = SessionLocal()
    try:
        user = db.scalars(select(Usuario).where(Usuario.correo == email)).first()
        assert user is not None
        session = db.scalars(
            select(Sesion).where(Sesion.id_usuario == user.id_usuario, Sesion.revocada.is_(False))
        ).first()
        assert session is not None
        db.expire_on_commit = False
        db.execute(
            update(Sesion)
            .where(Sesion.id_sesion == session.id_sesion)
            .values(revocada=True)
            .execution_options(synchronize_session=False)
        )
        db.commit()

        with pytest.raises(HTTPException) as error:
            MfaService(db).setup_mfa(user, session)
        assert error.value.status_code == 401
        assert not db.scalars(
            select(AutenticadorMfa).where(AutenticadorMfa.id_usuario == user.id_usuario)
        ).all()
    finally:
        db.close()
