from datetime import datetime, timedelta, timezone
import uuid

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import create_access_token
from app.main import app
from app.models.auth import Dispositivo, EventoAuditoria, Sesion, Usuario
from app.models.mfa import AutenticadorMfa
from app.models.policy import PoliticaSeguridad
from app.services.totp_secret_service import store_encrypted_totp_secret
from tests.helpers.device_identity import device_payload, new_device_identity


client = TestClient(app)
WEB_ORIGIN = settings.CORS_ORIGINS[0]


def _login(email: str, password: str) -> dict:
    identity = new_device_identity()
    response = client.post(
        "/api/v1/auth/login",
        json={
            "correo": email,
            "password": password,
            "dispositivo": device_payload(identity),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _mfa_admin_login() -> dict:
    db = SessionLocal()
    try:
        admin = db.scalars(select(Usuario).where(Usuario.correo == "admin@boveda.com")).first()
        assert admin is not None
        secret = pyotp.random_base32()
        authenticator = AutenticadorMfa(
            id_usuario=admin.id_usuario,
            tipo="TOTP",
            estado="ACTIVO",
        )
        store_encrypted_totp_secret(authenticator, secret)
        db.add(authenticator)
        db.commit()
    finally:
        db.close()

    pending = _login("admin@boveda.com", "Admin1234!*")
    assert pending["mfa_required"] is True
    verified = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": pending["mfa_token"], "code": pyotp.TOTP(secret).now()},
    )
    assert verified.status_code == 200, verified.text
    return verified.json()


def _policy(code: str) -> PoliticaSeguridad:
    db = SessionLocal()
    try:
        policy = db.scalars(
            select(PoliticaSeguridad).where(PoliticaSeguridad.codigo == code)
        ).first()
        assert policy is not None
        db.expunge(policy)
        return policy
    finally:
        db.close()


def _set_policy_value(code: str, value: int) -> None:
    db = SessionLocal()
    try:
        policy = db.scalars(
            select(PoliticaSeguridad).where(PoliticaSeguridad.codigo == code)
        ).first()
        assert policy is not None
        policy.valor_entero = value
        policy.version += 1
        db.commit()
    finally:
        db.close()


def test_effective_policies_are_authenticated_and_transparent_about_retention():
    member = _login("investigador@boveda.com", "User1234!*")
    response = client.get(
        "/api/v1/policies/effective",
        headers={"Authorization": f"Bearer {member['access_token']}"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["policies"]["INACTIVITY_TIMEOUT_MINUTES"] == 15
    assert payload["policies"]["VAULT_SESSION_DURATION_MINUTES"] == 5
    assert "AUDIT_RETENTION_DAYS" not in payload["policies"]
    retention = next(item for item in payload["items"] if item["codigo"] == "AUDIT_RETENTION_DAYS")
    assert retention["aplicada"] is False


def test_policy_read_and_write_require_permissions_and_recent_persisted_mfa():
    member = _login("investigador@boveda.com", "User1234!*")
    denied = client.get(
        "/api/v1/policies",
        headers={"Authorization": f"Bearer {member['access_token']}"},
    )
    assert denied.status_code == 403

    admin = _login("admin@boveda.com", "Admin1234!*")
    listed = client.get(
        "/api/v1/policies",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert listed.status_code == 200, listed.text
    inactivity = next(
        item for item in listed.json()["items"] if item["codigo"] == "INACTIVITY_TIMEOUT_MINUTES"
    )
    missing_mfa = client.put(
        "/api/v1/policies/INACTIVITY_TIMEOUT_MINUTES",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"valor": 20, "version": inactivity["version"]},
    )
    assert missing_mfa.status_code == 403
    assert "MFA" in missing_mfa.json()["detail"]

    stepped_up = _mfa_admin_login()
    updated = client.put(
        "/api/v1/policies/INACTIVITY_TIMEOUT_MINUTES",
        headers={"Authorization": f"Bearer {stepped_up['access_token']}"},
        json={"valor": 20, "version": inactivity["version"]},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["valor"] == 20
    assert updated.json()["version"] == inactivity["version"] + 1

    db = SessionLocal()
    try:
        audit = db.scalars(
            select(EventoAuditoria).where(
                EventoAuditoria.accion == "POLITICA_SEGURIDAD_ACTUALIZADA"
            )
        ).first()
        assert audit is not None
        assert audit.detalles == {
            "cambios": [
                {
                    "codigo": "INACTIVITY_TIMEOUT_MINUTES",
                    "anterior": 15,
                    "nuevo": 20,
                    "version_anterior": 1,
                }
            ]
        }
    finally:
        db.close()


def test_policy_write_uses_persisted_mfa_not_a_forged_access_claim():
    plain = _login("admin@boveda.com", "Admin1234!*")
    policy = _policy("LOCKOUT_DURATION_MINUTES")
    db = SessionLocal()
    try:
        admin = db.scalars(select(Usuario).where(Usuario.correo == "admin@boveda.com")).first()
        assert admin is not None
        session = db.scalars(
            select(Sesion).where(Sesion.id_usuario == admin.id_usuario)
        ).first()
        assert session is not None and session.id_dispositivo is not None
        forged = create_access_token(
            subject=admin.id_usuario,
            roles=["Administrador"],
            permissions=["policies:read", "policies:write"],
            session_id=session.id_sesion,
            device_id=session.id_dispositivo,
            mfa_verified_at=datetime.now(timezone.utc),
        )
    finally:
        db.close()

    response = client.put(
        "/api/v1/policies/LOCKOUT_DURATION_MINUTES",
        headers={"Authorization": f"Bearer {forged}"},
        json={"valor": 20, "version": policy.version},
    )
    assert response.status_code == 403
    assert "MFA" in response.json()["detail"]
    assert plain["access_token"]


def test_batch_updates_are_all_or_nothing_and_reject_duplicates():
    admin = _mfa_admin_login()
    first = _policy("INACTIVITY_TIMEOUT_MINUTES")
    second = _policy("PASSWORD_MIN_LENGTH")
    rejected = client.put(
        "/api/v1/policies/batch",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={
            "actualizaciones": [
                {"codigo": first.codigo, "valor": 25, "version": first.version},
                {"codigo": second.codigo, "valor": 129, "version": second.version},
            ]
        },
    )
    assert rejected.status_code == 422
    assert _policy(first.codigo).valor_entero == first.valor_entero
    assert _policy(second.codigo).valor_entero == second.valor_entero

    duplicate = client.put(
        "/api/v1/policies/batch",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={
            "actualizaciones": [
                {"codigo": first.codigo, "valor": 25, "version": first.version},
                {"codigo": first.codigo, "valor": 30, "version": first.version},
            ]
        },
    )
    assert duplicate.status_code == 422
    assert _policy(first.codigo).valor_entero == first.valor_entero


def test_policy_update_rolls_back_when_its_audit_event_cannot_be_written():
    admin = _mfa_admin_login()
    policy = _policy("MAX_FAILED_LOGIN_ATTEMPTS")

    def reject_audit_insert(_mapper, _connection, _target):
        raise RuntimeError("simulated policy audit failure")

    event.listen(EventoAuditoria, "before_insert", reject_audit_insert)
    try:
        with pytest.raises(RuntimeError, match="simulated policy audit failure"):
            client.put(
                "/api/v1/policies/MAX_FAILED_LOGIN_ATTEMPTS",
                headers={"Authorization": f"Bearer {admin['access_token']}"},
                json={"valor": 6, "version": policy.version},
            )
    finally:
        event.remove(EventoAuditoria, "before_insert", reject_audit_insert)

    restored = _policy("MAX_FAILED_LOGIN_ATTEMPTS")
    assert restored.valor_entero == policy.valor_entero
    assert restored.version == policy.version


def test_login_lockout_uses_the_current_policy_value():
    _set_policy_value("MAX_FAILED_LOGIN_ATTEMPTS", 3)
    for expected_status in (401, 401, 423):
        response = client.post(
            "/api/v1/auth/login",
            json={
                "correo": "investigador@boveda.com",
                "password": "ContraseñaIncorrecta123!*",
                "dispositivo": {"identificador_seguro": str(uuid.uuid4()), "tipo": "WEB"},
            },
        )
        assert response.status_code == expected_status

    db = SessionLocal()
    try:
        user = db.scalars(
            select(Usuario).where(Usuario.correo == "investigador@boveda.com")
        ).first()
        assert user is not None
        assert user.estado == "BLOQUEADO"
        assert user.intentos_fallidos == 3
    finally:
        db.close()


def test_password_policy_is_enforced_for_registration():
    _set_policy_value("PASSWORD_MIN_LENGTH", 16)
    response = client.post(
        "/api/v1/auth/register",
        json={
            "nombre": "Usuario Política",
            "correo": f"policy-{uuid.uuid4().hex}@boveda.com",
            "password": "StrongPass1!*",
        },
    )
    assert response.status_code == 422
    assert "16 caracteres" in response.json()["detail"]


def test_web_inactivity_lock_revokes_the_bound_session_without_trusting_device_headers():
    web_client = TestClient(app, base_url="https://testserver")
    login = web_client.post(
        "/api/v1/auth/web/login",
        json={"correo": "admin@boveda.com", "password": "Admin1234!*"},
        headers={"Origin": WEB_ORIGIN},
    )
    assert login.status_code == 200, login.text
    access_token = login.json()["access_token"]
    csrf_token = web_client.cookies.get(settings.CSRF_COOKIE_NAME)

    locked = web_client.post(
        "/api/v1/auth/web/inactivity-lock",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Origin": WEB_ORIGIN,
            "X-CSRF-Token": csrf_token,
            "X-Device-Id": "attacker-selected-device",
        },
    )
    assert locked.status_code == 204, locked.text
    assert web_client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    ).status_code == 401
    assert web_client.post(
        "/api/v1/auth/web/refresh",
        headers={"Origin": WEB_ORIGIN, "X-CSRF-Token": csrf_token},
    ).status_code == 401

    db = SessionLocal()
    try:
        event = db.scalars(
            select(EventoAuditoria).where(EventoAuditoria.accion == "BLOQUEO_INACTIVIDAD")
        ).first()
        assert event is not None
        device = db.get(Dispositivo, event.id_dispositivo)
        assert device is not None
        assert device.identificador_seguro != "attacker-selected-device"
        session = db.scalars(
            select(Sesion).where(Sesion.id_dispositivo == device.id_dispositivo)
        ).first()
        assert session is not None and session.revocada is True
        assert session.motivo_revocacion == "BLOQUEO_INACTIVIDAD"
    finally:
        db.close()


def test_inactivity_lock_does_not_refresh_an_already_idle_session_before_revoking_it():
    web_client = TestClient(app, base_url="https://testserver")
    login = web_client.post(
        "/api/v1/auth/web/login",
        json={"correo": "admin@boveda.com", "password": "Admin1234!*"},
        headers={"Origin": WEB_ORIGIN},
    )
    assert login.status_code == 200, login.text
    access_token = login.json()["access_token"]
    csrf_token = web_client.cookies.get(settings.CSRF_COOKIE_NAME)
    _set_policy_value("INACTIVITY_TIMEOUT_MINUTES", 1)

    db = SessionLocal()
    try:
        session = db.scalars(select(Sesion).where(Sesion.tipo_cliente == "WEB")).first()
        assert session is not None
        session.ultima_actividad = datetime.now(timezone.utc) - timedelta(minutes=2)
        db.commit()
    finally:
        db.close()

    locked = web_client.post(
        "/api/v1/auth/web/inactivity-lock",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Origin": WEB_ORIGIN,
            "X-CSRF-Token": csrf_token,
        },
    )
    assert locked.status_code == 204, locked.text

    db = SessionLocal()
    try:
        event = db.scalars(
            select(EventoAuditoria).where(EventoAuditoria.accion == "BLOQUEO_INACTIVIDAD")
        ).first()
        assert event is not None
        assert event.detalles["origen"] == "CLIENTE_WEB"
    finally:
        db.close()


def test_web_inactivity_lock_requires_the_current_csrf_token():
    web_client = TestClient(app, base_url="https://testserver")
    login = web_client.post(
        "/api/v1/auth/web/login",
        json={"correo": "admin@boveda.com", "password": "Admin1234!*"},
        headers={"Origin": WEB_ORIGIN},
    )
    assert login.status_code == 200, login.text
    access_token = login.json()["access_token"]

    rejected = web_client.post(
        "/api/v1/auth/web/inactivity-lock",
        headers={"Authorization": f"Bearer {access_token}", "Origin": WEB_ORIGIN},
    )
    assert rejected.status_code == 403
    assert "CSRF" in rejected.json()["detail"]
    assert web_client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    ).status_code == 200


def test_server_rejects_an_idle_web_session_even_when_the_client_skips_the_lock_screen():
    web_client = TestClient(app, base_url="https://testserver")
    login = web_client.post(
        "/api/v1/auth/web/login",
        json={"correo": "admin@boveda.com", "password": "Admin1234!*"},
        headers={"Origin": WEB_ORIGIN},
    )
    assert login.status_code == 200, login.text
    access_token = login.json()["access_token"]
    _set_policy_value("INACTIVITY_TIMEOUT_MINUTES", 1)

    db = SessionLocal()
    try:
        session = db.scalars(select(Sesion).where(Sesion.tipo_cliente == "WEB")).first()
        assert session is not None
        session.ultima_actividad = datetime.now(timezone.utc) - timedelta(minutes=2)
        db.commit()
    finally:
        db.close()

    rejected = web_client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert rejected.status_code == 401
    assert "inactividad" in rejected.json()["detail"]
