import base64
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.main import app
from app.models.auth import DesafioDispositivo, Dispositivo, EventoAuditoria, Sesion
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


def test_valid_challenge_marks_device_trusted_and_audits():
    identity, login = _admin_login()
    proof = prove_challenge(client, login["access_token"], identity, "DEVICE_ENROLLMENT")
    assert proof["dispositivo"]["estado"] == "TRUSTED"
    assert proof["dispositivo"]["es_confiable"] is True

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
    trusted = prove_challenge(client, access_token, identity, "DEVICE_ENROLLMENT")
    device_id = trusted["dispositivo"]["id_dispositivo"]

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
