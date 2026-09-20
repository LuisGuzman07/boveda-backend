import base64
from datetime import datetime, timezone
import uuid

import pyotp
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.core.database import SessionLocal
from app.core.security import create_access_token
from app.main import app
from app.models.auth import DesafioDispositivo, Dispositivo, EventoAuditoria, Sesion, Usuario
from app.models.mfa import AutenticadorMfa
from app.services.totp_secret_service import store_encrypted_totp_secret
from app.services.auth_service import AuthenticatedSession
from app.services.device_identity_service import DeviceIdentityService
from app.services.device_service import DeviceService
from tests.helpers.device_identity import (
    current_device,
    device_payload,
    login_with_device,
    new_device_identity,
    prove_challenge,
)


client = TestClient(app)


def _admin_login(identity=None):
    identity = identity or new_device_identity()
    data = login_with_device(client, "admin@boveda.com", "Admin1234!*", identity)
    return identity, data


def _mfa_login(email: str, password: str, identity):
    db = SessionLocal()
    try:
        user = db.scalars(select(Usuario).where(Usuario.correo == email)).first()
        assert user is not None
        secret = pyotp.random_base32()
        mfa = AutenticadorMfa(id_usuario=user.id_usuario, tipo="TOTP", estado="ACTIVO")
        store_encrypted_totp_secret(mfa, secret)
        db.add(mfa)
        db.commit()
    finally:
        db.close()

    pending = login_with_device(client, email, password, identity)
    assert pending["mfa_required"] is True
    verified = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": pending["mfa_token"], "code": pyotp.TOTP(secret).now()},
    )
    assert verified.status_code == 200, verified.text
    return verified.json()


def _approve_as_admin(device_id: str):
    approver = _mfa_login(
        "admin@boveda.com",
        "Admin1234!*",
        new_device_identity(),
    )
    response = client.post(
        f"/api/v1/devices/admin/{device_id}/approve",
        headers={"Authorization": f"Bearer {approver['access_token']}"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_registration_is_pending_and_client_cannot_self_trust():
    identity, login = _admin_login()
    access_token = login["access_token"]
    device = current_device(client, access_token)
    assert device["estado"] == "PENDING"
    assert device["es_confiable"] is False

    legacy_flag = client.post(
        "/api/v1/auth/login",
        json={
            "correo": "admin@boveda.com",
            "password": "Admin1234!*",
            "confiar_dispositivo": True,
            "dispositivo": {**device_payload(new_device_identity()), "confiar_dispositivo": True},
        },
    )
    assert legacy_flag.status_code == 200
    legacy_token = legacy_flag.json()["access_token"]
    assert current_device(client, legacy_token)["estado"] == "PENDING"

    direct = client.post(
        f"/api/v1/devices/{device['id_dispositivo']}/authorize",
        json={"nombre": "No debe funcionar"},
    )
    assert direct.status_code == 410


def test_valid_challenge_records_possession_without_granting_trust():
    identity, login = _admin_login()
    proof = prove_challenge(client, login["access_token"], identity, "DEVICE_ENROLLMENT")
    assert proof["dispositivo"]["estado"] == "PENDING"
    assert proof["dispositivo"]["es_confiable"] is False
    assert proof["dispositivo"]["identidad_verificada_en"] is not None
    assert proof["dispositivo"]["confianza_otorgada_en"] is None

    db = SessionLocal()
    try:
        event = db.scalars(
            select(EventoAuditoria).where(
                EventoAuditoria.accion == "IDENTIDAD_DISPOSITIVO_VERIFICADA"
            )
        ).first()
        assert event is not None
        assert event.resultado == "EXITO"
    finally:
        db.close()


def test_administrator_with_recent_mfa_approves_another_verified_device():
    member_identity = new_device_identity()
    member = login_with_device(
        client,
        "investigador@boveda.com",
        "User1234!*",
        member_identity,
    )
    proof = prove_challenge(
        client,
        member["access_token"],
        member_identity,
        "DEVICE_ENROLLMENT",
    )
    approved = _approve_as_admin(proof["dispositivo"]["id_dispositivo"])

    device = approved["dispositivo"]
    assert device["estado"] == "TRUSTED"
    assert device["es_confiable"] is True
    assert device["confianza_otorgada_en"] is not None
    assert device["confianza_otorgada_por"] is not None

    db = SessionLocal()
    try:
        event = db.scalars(
            select(EventoAuditoria).where(
                EventoAuditoria.accion == "APROBACION_DISPOSITIVO_ADMIN",
                EventoAuditoria.id_dispositivo == uuid.UUID(device["id_dispositivo"]),
            )
        ).first()
        assert event is not None
        assert event.resultado == "EXITO"
    finally:
        db.close()


def test_user_cannot_self_approve_or_skip_possession_proof():
    identity = new_device_identity()
    admin = _mfa_login("admin@boveda.com", "Admin1234!*", identity)
    device = current_device(client, admin["access_token"])

    skipped = client.post(
        f"/api/v1/devices/admin/{device['id_dispositivo']}/approve",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert skipped.status_code == 403
    assert "propio" in skipped.json()["detail"]

    member_identity = new_device_identity()
    member = login_with_device(
        client,
        "investigador@boveda.com",
        "User1234!*",
        member_identity,
    )
    member_device = current_device(client, member["access_token"])
    missing_proof = client.post(
        f"/api/v1/devices/admin/{member_device['id_dispositivo']}/approve",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert missing_proof.status_code == 409
    assert "posesión" in missing_proof.json()["detail"]


def test_approval_uses_server_side_mfa_not_a_forged_access_claim():
    member_identity = new_device_identity()
    member = login_with_device(
        client,
        "investigador@boveda.com",
        "User1234!*",
        member_identity,
    )
    proof = prove_challenge(
        client,
        member["access_token"],
        member_identity,
        "DEVICE_ENROLLMENT",
    )
    admin_identity, admin = _admin_login()
    admin_device = current_device(client, admin["access_token"])
    db = SessionLocal()
    try:
        session = db.scalars(
            select(Sesion).where(
                Sesion.id_dispositivo == uuid.UUID(admin_device["id_dispositivo"])
            )
        ).first()
        assert session is not None
        forged = create_access_token(
            subject=uuid.UUID(admin_device["id_usuario"]),
            roles=["Administrador"],
            permissions=["devices:approve"],
            session_id=session.id_sesion,
            device_id=session.id_dispositivo,
            mfa_verified_at=datetime.now(timezone.utc),
        )
    finally:
        db.close()

    denied = client.post(
        f"/api/v1/devices/admin/{proof['dispositivo']['id_dispositivo']}/approve",
        headers={"Authorization": f"Bearer {forged}"},
    )
    assert denied.status_code == 403
    assert "MFA" in denied.json()["detail"]


def test_approval_rechecks_a_revoked_admin_session_at_the_mutation_boundary():
    member_identity = new_device_identity()
    member = login_with_device(
        client,
        "investigador@boveda.com",
        "User1234!*",
        member_identity,
    )
    target = prove_challenge(
        client,
        member["access_token"],
        member_identity,
        "DEVICE_ENROLLMENT",
    )["dispositivo"]
    admin_identity = new_device_identity()
    _mfa_login("admin@boveda.com", "Admin1234!*", admin_identity)

    db = SessionLocal()
    try:
        admin = db.scalars(select(Usuario).where(Usuario.correo == "admin@boveda.com")).first()
        assert admin is not None
        admin_device = db.scalars(
            select(Dispositivo).where(
                Dispositivo.id_usuario == admin.id_usuario,
                Dispositivo.identificador_seguro == admin_identity.installation_id,
            )
        ).first()
        assert admin_device is not None
        admin_session = db.scalars(
            select(Sesion).where(Sesion.id_dispositivo == admin_device.id_dispositivo)
        ).first()
        assert admin_session is not None
        # Keep the identity map stale to emulate a dependency that ran before revocation.
        _ = [permission.codigo for role in admin.roles for permission in role.permisos]
        context = AuthenticatedSession(admin, admin_session, admin_device, {})
        db.expire_on_commit = False
        db.execute(
            update(Sesion)
            .where(Sesion.id_sesion == admin_session.id_sesion)
            .values(revocada=True)
            .execution_options(synchronize_session=False)
        )
        db.commit()

        with pytest.raises(HTTPException) as error:
            DeviceService(db).approve_device_admin(
                uuid.UUID(target["id_dispositivo"]), context
            )
        assert error.value.status_code == 401

        db.expire_all()
        assert db.get(Dispositivo, uuid.UUID(target["id_dispositivo"])).estado == "PENDING"
    finally:
        db.close()


def test_device_challenge_rechecks_a_revoked_session_at_the_mutation_boundary():
    identity, _ = _admin_login()
    db = SessionLocal()
    try:
        user = db.scalars(select(Usuario).where(Usuario.correo == "admin@boveda.com")).first()
        assert user is not None
        device = db.scalars(
            select(Dispositivo).where(
                Dispositivo.id_usuario == user.id_usuario,
                Dispositivo.identificador_seguro == identity.installation_id,
            )
        ).first()
        assert device is not None
        session = db.scalars(select(Sesion).where(Sesion.id_dispositivo == device.id_dispositivo)).first()
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
            DeviceIdentityService(db).issue_challenge(
                user, session, device, "DEVICE_ENROLLMENT"
            )
        assert error.value.status_code == 401
    finally:
        db.close()


def test_admin_revocation_rechecks_a_revoked_session_at_the_mutation_boundary():
    member_identity = new_device_identity()
    member = login_with_device(
        client,
        "investigador@boveda.com",
        "User1234!*",
        member_identity,
    )
    target = current_device(client, member["access_token"])
    admin_identity = new_device_identity()
    _mfa_login("admin@boveda.com", "Admin1234!*", admin_identity)

    db = SessionLocal()
    try:
        admin = db.scalars(select(Usuario).where(Usuario.correo == "admin@boveda.com")).first()
        assert admin is not None
        admin_device = db.scalars(
            select(Dispositivo).where(
                Dispositivo.id_usuario == admin.id_usuario,
                Dispositivo.identificador_seguro == admin_identity.installation_id,
            )
        ).first()
        assert admin_device is not None
        admin_session = db.scalars(
            select(Sesion).where(Sesion.id_dispositivo == admin_device.id_dispositivo)
        ).first()
        assert admin_session is not None
        _ = [permission.codigo for role in admin.roles for permission in role.permisos]
        context = AuthenticatedSession(admin, admin_session, admin_device, {})
        db.expire_on_commit = False
        db.execute(
            update(Sesion)
            .where(Sesion.id_sesion == admin_session.id_sesion)
            .values(revocada=True)
            .execution_options(synchronize_session=False)
        )
        db.commit()

        with pytest.raises(HTTPException) as error:
            DeviceService(db).revoke_device_admin(
                uuid.UUID(target["id_dispositivo"]), context, "Prueba de sesión revocada"
            )
        assert error.value.status_code == 401

        db.expire_all()
        assert db.get(Dispositivo, uuid.UUID(target["id_dispositivo"])).estado == "PENDING"
    finally:
        db.close()


def test_web_administrative_approval_requires_an_allowed_origin():
    member_identity = new_device_identity()
    member = login_with_device(
        client,
        "investigador@boveda.com",
        "User1234!*",
        member_identity,
    )
    proof = prove_challenge(
        client,
        member["access_token"],
        member_identity,
        "DEVICE_ENROLLMENT",
    )

    db = SessionLocal()
    try:
        admin = db.scalars(select(Usuario).where(Usuario.correo == "admin@boveda.com")).first()
        assert admin is not None
        secret = pyotp.random_base32()
        mfa = AutenticadorMfa(id_usuario=admin.id_usuario, tipo="TOTP", estado="ACTIVO")
        store_encrypted_totp_secret(mfa, secret)
        db.add(mfa)
        db.commit()
    finally:
        db.close()

    web_client = TestClient(app, base_url="https://testserver")
    origin = "http://localhost:5173"
    login = web_client.post(
        "/api/v1/auth/web/login",
        json={"correo": "admin@boveda.com", "password": "Admin1234!*"},
        headers={"Origin": origin},
    )
    assert login.status_code == 200
    verified = web_client.post(
        "/api/v1/auth/web/mfa/verify-login",
        json={"mfa_token": login.json()["mfa_token"], "code": pyotp.TOTP(secret).now()},
        headers={"Origin": origin},
    )
    assert verified.status_code == 200
    headers = {"Authorization": f"Bearer {verified.json()['access_token']}"}

    missing = web_client.post(
        f"/api/v1/devices/admin/{proof['dispositivo']['id_dispositivo']}/approve",
        headers=headers,
    )
    foreign = web_client.post(
        f"/api/v1/devices/admin/{proof['dispositivo']['id_dispositivo']}/approve",
        headers={**headers, "Origin": "https://attacker.invalid"},
    )
    allowed = web_client.post(
        f"/api/v1/devices/admin/{proof['dispositivo']['id_dispositivo']}/approve",
        headers={**headers, "Origin": origin},
    )
    assert missing.status_code == foreign.status_code == 403
    assert allowed.status_code == 200


def test_login_rejects_replacing_registered_device_keys():
    identity, _ = _admin_login()
    replacement = new_device_identity()
    replacement_payload = device_payload(replacement)
    replacement_payload["identificador_seguro"] = identity.installation_id

    installation_key_response = client.post(
        "/api/v1/auth/login",
        json={
            "correo": "admin@boveda.com",
            "password": "Admin1234!*",
            "dispositivo": replacement_payload,
        },
    )
    assert installation_key_response.status_code == 409

    vault_identity = new_device_identity()
    keyed_identity = new_device_identity()
    login_with_device(
        client,
        "investigador@boveda.com",
        "User1234!*",
        keyed_identity,
        vault_public_key=vault_identity.public_key,
    )
    vault_key_response = client.post(
        "/api/v1/auth/login",
        json={
            "correo": "investigador@boveda.com",
            "password": "User1234!*",
            "dispositivo": device_payload(
                keyed_identity, vault_public_key=new_device_identity().public_key
            ),
        },
    )
    assert vault_key_response.status_code == 409


def test_invalid_or_replayed_challenge_is_rejected():
    identity, login = _admin_login()
    access_token = login["access_token"]
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Device-Id": identity.installation_id,
    }
    issued = client.post(
        "/api/v1/devices/challenge",
        headers=headers,
        json={"proposito": "DEVICE_ENROLLMENT"},
    )
    challenge = issued.json()
    invalid = client.post(
        "/api/v1/devices/challenge/prove",
        headers=headers,
        json={
            "id_desafio": challenge["id_desafio"],
            "nonce": challenge["nonce"],
            "firma": base64.b64encode(bytes(64)).decode("ascii"),
        },
    )
    assert invalid.status_code == 401

    replay = client.post(
        "/api/v1/devices/challenge/prove",
        headers=headers,
        json={
            "id_desafio": challenge["id_desafio"],
            "nonce": challenge["nonce"],
            "firma": base64.b64encode(bytes(64)).decode("ascii"),
        },
    )
    assert replay.status_code == 401

    db = SessionLocal()
    try:
        stored = db.get(DesafioDispositivo, uuid.UUID(challenge["id_desafio"]))
        assert stored is not None
        assert stored.consumido_en is not None
    finally:
        db.close()


def test_revocation_invalidates_session_and_device_identity():
    identity, login = _admin_login()
    access_token = login["access_token"]
    proven = prove_challenge(client, access_token, identity, "DEVICE_ENROLLMENT")
    device_id = proven["dispositivo"]["id_dispositivo"]

    revoked = client.delete(
        f"/api/v1/devices/{device_id}", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert revoked.status_code == 200
    assert revoked.json()["dispositivo"]["estado"] == "REVOKED"
    assert client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    ).status_code == 401

    db = SessionLocal()
    try:
        session = db.scalars(select(Sesion).where(Sesion.id_dispositivo == uuid.UUID(device_id))).first()
        assert session is not None and session.revocada is True
    finally:
        db.close()


def test_revoked_identifier_or_public_key_cannot_be_reenrolled():
    identity, login = _admin_login()
    device = current_device(client, login["access_token"])
    revoked = client.delete(
        f"/api/v1/devices/{device['id_dispositivo']}",
        headers={"Authorization": f"Bearer {login['access_token']}"},
    )
    assert revoked.status_code == 200

    reused_identifier = client.post(
        "/api/v1/auth/login",
        json={
            "correo": "investigador@boveda.com",
            "password": "User1234!*",
            "dispositivo": device_payload(identity),
        },
    )
    assert reused_identifier.status_code == 403

    fresh = login_with_device(
        client,
        "admin@boveda.com",
        "Admin1234!*",
        new_device_identity(),
    )
    assert current_device(client, fresh["access_token"])["estado"] == "PENDING"


def test_revocation_wins_over_pending_proof_approval_and_refresh():
    identity = new_device_identity()
    member = login_with_device(
        client,
        "investigador@boveda.com",
        "User1234!*",
        identity,
    )
    access_token = member["access_token"]
    device = current_device(client, access_token)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Device-Id": identity.installation_id,
    }
    challenge = client.post(
        "/api/v1/devices/challenge",
        headers=headers,
        json={"proposito": "DEVICE_ENROLLMENT"},
    )
    assert challenge.status_code == 200

    revoked = client.delete(
        f"/api/v1/devices/{device['id_dispositivo']}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert revoked.status_code == 200

    # The previously issued challenge and refresh family cannot race revocation.
    stale_proof = client.post(
        "/api/v1/devices/challenge/prove",
        headers=headers,
        json={
            "id_desafio": challenge.json()["id_desafio"],
            "nonce": challenge.json()["nonce"],
            "firma": base64.b64encode(bytes(64)).decode("ascii"),
        },
    )
    assert stale_proof.status_code == 401
    assert client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": member["refresh_token"]},
    ).status_code == 401

    approver = _mfa_login("admin@boveda.com", "Admin1234!*", new_device_identity())
    approval = client.post(
        f"/api/v1/devices/admin/{device['id_dispositivo']}/approve",
        headers={"Authorization": f"Bearer {approver['access_token']}"},
    )
    assert approval.status_code == 403


def test_non_owner_cannot_revoke_a_device():
    owner_identity, owner_login = _admin_login()
    owner_device = current_device(client, owner_login["access_token"])
    member_identity = new_device_identity()
    member_login = login_with_device(
        client, "investigador@boveda.com", "User1234!*", member_identity
    )
    response = client.delete(
        f"/api/v1/devices/{owner_device['id_dispositivo']}",
        headers={"Authorization": f"Bearer {member_login['access_token']}"},
    )
    assert response.status_code == 404
