import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import time
import uuid

import jwt
import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, func, select
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import get_jwt_secret
from app.main import app
from app.models.auth import Dispositivo, EventoAuditoria, Sesion, SesionBoveda, Usuario
from app.models.mfa import AutenticadorMfa
from app.models.vault import Boveda, ClaveEnvuelta, MembresiaBoveda
from app.services.totp_secret_service import store_encrypted_totp_secret
from tests.helpers.device_identity import (
    current_device,
    login_with_device,
    new_device_identity,
    prove_challenge,
)


client = TestClient(app)


def _enable_mfa(email: str) -> str:
    db = SessionLocal()
    try:
        user = db.scalars(select(Usuario).where(Usuario.correo == email)).first()
        assert user is not None
        for existing in db.scalars(
            select(AutenticadorMfa).where(
                AutenticadorMfa.id_usuario == user.id_usuario,
                AutenticadorMfa.estado == "ACTIVO",
            )
        ).all():
            existing.estado = "REVOCADO"
        secret = pyotp.random_base32()
        mfa = AutenticadorMfa(id_usuario=user.id_usuario, tipo="TOTP", estado="ACTIVO")
        store_encrypted_totp_secret(mfa, secret)
        db.add(mfa)
        db.commit()
        return secret
    finally:
        db.close()


def _vault_public_key(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")


def _mfa_login(identity, vault_signing_key, email="investigador@boveda.com", password="User1234!*"):
    secret = _enable_mfa(email)
    login = login_with_device(
        client,
        email,
        password,
        identity,
        _vault_public_key(vault_signing_key),
    )
    assert login["mfa_required"] is True
    verified = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": login["mfa_token"], "code": pyotp.TOTP(secret).now()},
    )
    assert verified.status_code == 200, verified.text
    return verified.json()


def _approve_device(device_id: str):
    approver_identity = new_device_identity()
    approver = _mfa_login(
        approver_identity,
        Ed25519PrivateKey.generate(),
        email="admin@boveda.com",
        password="Admin1234!*",
    )
    response = client.post(
        f"/api/v1/devices/admin/{device_id}/approve",
        headers={"Authorization": f"Bearer {approver['access_token']}"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _vault_session(identity, email="investigador@boveda.com", password="User1234!*"):
    vault_signing_key = Ed25519PrivateKey.generate()
    login = _mfa_login(identity, vault_signing_key, email=email, password=password)
    access_token = login["access_token"]
    proof = prove_challenge(client, access_token, identity, "DEVICE_ENROLLMENT")
    assert proof["dispositivo"]["estado"] == "PENDING"
    approved = _approve_device(proof["dispositivo"]["id_dispositivo"])
    assert approved["dispositivo"]["estado"] == "TRUSTED"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Device-Id": identity.installation_id,
    }
    challenge = client.post(
        "/api/v1/devices/challenge",
        headers=headers,
        json={"proposito": "VAULT_SESSION"},
    )
    assert challenge.status_code == 200, challenge.text
    issued = challenge.json()
    device = current_device(client, access_token)
    from datetime import datetime
    from app.services.device_identity_service import challenge_transcript

    expires_at = datetime.fromisoformat(issued["fecha_expiracion"].replace("Z", "+00:00"))
    message = challenge_transcript(
        uuid.UUID(issued["id_desafio"]),
        "VAULT_SESSION",
        uuid.UUID(device["id_usuario"]),
        uuid.UUID(device["id_dispositivo"]),
        issued["nonce"],
        expires_at,
    )
    response = client.post(
        "/api/v1/vaults/session",
        headers=headers,
        json={
            "id_desafio": issued["id_desafio"],
            "nonce": issued["nonce"],
            "firma": base64.b64encode(identity.private_key.sign(message)).decode("ascii"),
        },
    )
    assert response.status_code == 200, response.text
    return response.json(), access_token, device, vault_signing_key


def _envelope(length=32):
    return {
        "algoritmo": "AES-256-GCM",
        "ciphertext": base64.b64encode(bytes(length)).decode("ascii"),
        "nonce": base64.b64encode(bytes(12)).decode("ascii"),
        "tag": base64.b64encode(bytes(16)).decode("ascii"),
    }


def _creation(device):
    return {
        "id_boveda": str(uuid.uuid4()),
        "nombre_cifrado": _envelope(),
        "descripcion_cifrada": None,
        "version_criptografica": 1,
        "kdf_salt": base64.b64encode(bytes(16)).decode("ascii"),
        "kdf_parametros": {
            "algoritmo": "Argon2id",
            "memoria_kib": 65536,
            "iteraciones": 3,
            "paralelismo": 1,
            "longitud": 32,
        },
        "clave_envuelta": {
            **_envelope(200),
            "id_dispositivo": device["id_dispositivo"],
            "version_clave": 1,
        },
    }


def _signed_request(
    signing_key,
    vault_token,
    method,
    path,
    body=None,
    retry_key="vault-retry-key-0001",
    timestamp=None,
    http_client=None,
):
    text = json.dumps(body, separators=(",", ":")) if body is not None else ""
    payload = jwt.decode(vault_token, get_jwt_secret(), algorithms=[settings.JWT_ALGORITHM])
    timestamp = str(timestamp if timestamp is not None else int(time.time()))
    message = "\n".join(
        [
            payload["jti"],
            timestamp,
            method,
            path,
            retry_key,
            hashlib.sha256(text.encode("utf-8")).hexdigest(),
        ]
    ).encode("utf-8")
    return (http_client or client).request(
        method,
        path,
        content=text,
        headers={
            "Authorization": f"Bearer {vault_token}",
            "Content-Type": "application/json",
            "Idempotency-Key": retry_key,
            "X-Vault-Timestamp": timestamp,
            "X-Vault-Signature": base64.b64encode(signing_key.sign(message)).decode("ascii"),
        },
    )


def test_vault_requires_mfa_trusted_identity_and_one_time_proof():
    identity = new_device_identity()
    vault, _, device, vault_signing_key = _vault_session(identity)
    body = _creation(device)
    created = _signed_request(vault_signing_key, vault["access_token"], "POST", "/api/v1/vaults", body)
    assert created.status_code == 201, created.text
    assert _signed_request(
        vault_signing_key, vault["access_token"], "GET", f"/api/v1/vaults/{body['id_boveda']}"
    ).status_code == 200

    db = SessionLocal()
    try:
        session = db.scalars(select(SesionBoveda)).first()
        assert session is not None
        assert session.revocada is False
        assert db.scalars(select(Boveda)).first() is not None
    finally:
        db.close()


def test_vault_preserves_idempotency_and_rejects_invalid_bound_envelopes():
    identity = new_device_identity()
    vault, _, device, vault_signing_key = _vault_session(identity)
    token = vault["access_token"]
    body = _creation(device)

    created = _signed_request(vault_signing_key, token, "POST", "/api/v1/vaults", body)
    retried = _signed_request(vault_signing_key, token, "POST", "/api/v1/vaults", body)
    assert created.status_code == retried.status_code == 201
    assert created.json() == retried.json()

    conflicting = _creation(device)
    assert _signed_request(
        vault_signing_key, token, "POST", "/api/v1/vaults", conflicting
    ).status_code == 409

    wrong_device = _creation(device)
    wrong_device["clave_envuelta"]["id_dispositivo"] = str(uuid.uuid4())
    assert _signed_request(
        vault_signing_key,
        token,
        "POST",
        "/api/v1/vaults",
        wrong_device,
        retry_key="vault-wrong-device-0001",
    ).status_code == 403

    malformed = _creation(device)
    malformed["nombre_cifrado"]["nonce"] = base64.b64encode(bytes(8)).decode("ascii")
    assert _signed_request(
        vault_signing_key,
        token,
        "POST",
        "/api/v1/vaults",
        malformed,
        retry_key="vault-invalid-envelope-0001",
    ).status_code == 422


def test_vault_session_rejects_missing_mfa_and_revocation_is_immediate():
    identity = new_device_identity()
    plain_login = login_with_device(client, "investigador@boveda.com", "User1234!*", identity)
    access = plain_login["access_token"]
    proof = prove_challenge(client, access, identity, "DEVICE_ENROLLMENT")
    _approve_device(proof["dispositivo"]["id_dispositivo"])
    denied = client.post(
        "/api/v1/devices/challenge",
        headers={"Authorization": f"Bearer {access}", "X-Device-Id": identity.installation_id},
        json={"proposito": "VAULT_SESSION"},
    )
    assert denied.status_code == 403

    identity = new_device_identity()
    vault, access, device, vault_signing_key = _vault_session(identity)
    revoked = client.delete(
        f"/api/v1/devices/{device['id_dispositivo']}",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert revoked.status_code == 200
    assert _signed_request(
        vault_signing_key, vault["access_token"], "GET", "/api/v1/vaults"
    ).status_code == 401


def test_remote_vault_session_validation_and_revocation_are_signed_and_immediate():
    identity = new_device_identity()
    vault, _, _, vault_signing_key = _vault_session(identity)
    token = vault["access_token"]

    active = _signed_request(vault_signing_key, token, "GET", "/api/v1/vaults/session")
    assert active.status_code == 200
    assert active.json() == {"status": "active"}

    revoked = _signed_request(vault_signing_key, token, "DELETE", "/api/v1/vaults/session")
    assert revoked.status_code == 204
    assert _signed_request(vault_signing_key, token, "GET", "/api/v1/vaults/session").status_code == 401


def test_vault_requires_a_signed_device_bound_session():
    identity = new_device_identity()
    vault, _, device, vault_signing_key = _vault_session(identity)
    body = _creation(device)
    assert client.post(
        "/api/v1/vaults",
        json=body,
        headers={"Idempotency-Key": "vault-missing-session-0001"},
    ).status_code == 401
    assert client.get(
        "/api/v1/vaults",
        headers={"Authorization": f"Bearer {vault['access_token']}"},
    ).status_code == 401
    assert _signed_request(
        vault_signing_key,
        vault["access_token"],
        "POST",
        "/api/v1/vaults",
        body,
        timestamp=int(time.time()) - 120,
    ).status_code == 401


@pytest.mark.parametrize("invalid_state", ["session", "device", "trust", "user", "permission", "key"])
def test_vault_rejects_revoked_or_untrusted_server_state(invalid_state):
    identity = new_device_identity()
    vault, _, device_data, vault_signing_key = _vault_session(identity)
    db = SessionLocal()
    try:
        device = db.get(Dispositivo, uuid.UUID(device_data["id_dispositivo"]))
        assert device is not None
        session = db.scalars(
            select(Sesion).where(Sesion.id_dispositivo == device.id_dispositivo)
        ).first()
        user = db.get(Usuario, device.id_usuario)
        assert session is not None and user is not None
        if invalid_state == "session":
            session.revocada = True
        elif invalid_state == "device":
            device.estado = "REVOKED"
        elif invalid_state == "trust":
            device.es_confiable = False
        elif invalid_state == "user":
            user.estado = "INACTIVO"
        elif invalid_state == "permission":
            user.roles = []
        else:
            device.clave_firma_boveda = new_device_identity().public_key
        db.commit()
    finally:
        db.close()

    rejected = _signed_request(
        vault_signing_key,
        vault["access_token"],
        "POST",
        "/api/v1/vaults",
        _creation(device_data),
    )
    assert rejected.status_code in {401, 403}


def test_vault_creation_rolls_back_when_its_audit_record_fails():
    identity = new_device_identity()
    vault, _, device, vault_signing_key = _vault_session(identity)
    body = _creation(device)
    retry_key = "vault-audit-rollback-0001"

    def reject_audit_insert(_mapper, _connection, _target):
        raise RuntimeError("simulated audit failure")

    event.listen(EventoAuditoria, "before_insert", reject_audit_insert)
    try:
        with pytest.raises(RuntimeError, match="simulated audit failure"):
            _signed_request(
                vault_signing_key,
                vault["access_token"],
                "POST",
                "/api/v1/vaults",
                body,
                retry_key=retry_key,
            )
    finally:
        event.remove(EventoAuditoria, "before_insert", reject_audit_insert)

    db = SessionLocal()
    try:
        vault_id = uuid.UUID(body["id_boveda"])
        assert db.scalar(select(func.count()).select_from(Boveda).where(Boveda.id_boveda == vault_id)) == 0
        assert db.scalar(
            select(func.count()).select_from(MembresiaBoveda).where(MembresiaBoveda.id_boveda == vault_id)
        ) == 0
        assert db.scalar(
            select(func.count()).select_from(ClaveEnvuelta).where(ClaveEnvuelta.id_boveda == vault_id)
        ) == 0
        assert db.scalar(
            select(func.count())
            .select_from(EventoAuditoria)
            .where(
                EventoAuditoria.accion == "CREAR_BOVEDA",
                EventoAuditoria.recurso_id == body["id_boveda"],
            )
        ) == 0
    finally:
        db.close()

    created = _signed_request(
        vault_signing_key,
        vault["access_token"],
        "POST",
        "/api/v1/vaults",
        body,
        retry_key=retry_key,
    )
    retried = _signed_request(
        vault_signing_key,
        vault["access_token"],
        "POST",
        "/api/v1/vaults",
        body,
        retry_key=retry_key,
    )
    assert created.status_code == retried.status_code == 201
    assert created.json() == retried.json()

    db = SessionLocal()
    try:
        vault_id = uuid.UUID(body["id_boveda"])
        assert db.scalar(select(func.count()).select_from(Boveda).where(Boveda.id_boveda == vault_id)) == 1
        assert db.scalar(
            select(func.count()).select_from(MembresiaBoveda).where(MembresiaBoveda.id_boveda == vault_id)
        ) == 1
        assert db.scalar(
            select(func.count()).select_from(ClaveEnvuelta).where(ClaveEnvuelta.id_boveda == vault_id)
        ) == 1
        assert db.scalar(
            select(func.count())
            .select_from(EventoAuditoria)
            .where(
                EventoAuditoria.accion == "CREAR_BOVEDA",
                EventoAuditoria.recurso_id == body["id_boveda"],
            )
        ) == 1
    finally:
        db.close()


def test_vault_envelopes_are_isolated_by_user_and_trusted_device():
    owner_identity = new_device_identity()
    vault, owner_access_token, owner_device, owner_signing_key = _vault_session(owner_identity)
    body = _creation(owner_device)
    created = _signed_request(owner_signing_key, vault["access_token"], "POST", "/api/v1/vaults", body)
    assert created.status_code == 201

    other_owner_device_identity = new_device_identity()
    other_owner_vault, _, other_owner_device, other_owner_signing_key = _vault_session(
        other_owner_device_identity
    )
    other_owner_list = _signed_request(
        other_owner_signing_key,
        other_owner_vault["access_token"],
        "GET",
        "/api/v1/vaults",
    )
    assert other_owner_list.status_code == 200
    assert other_owner_list.json() == {"items": []}
    assert _signed_request(
        other_owner_signing_key,
        other_owner_vault["access_token"],
        "GET",
        f"/api/v1/vaults/{body['id_boveda']}",
    ).status_code == 404

    other_email = f"vault-isolation-{uuid.uuid4().hex}@boveda.com"
    other_password = f"Vault-{uuid.uuid4().hex}-1!"
    registered = client.post(
        "/api/v1/auth/register",
        json={
            "nombre": "Usuario de aislamiento",
            "correo": other_email,
            "password": other_password,
        },
    )
    assert registered.status_code == 201, registered.text
    stranger_identity = new_device_identity()
    stranger_vault, _, _, stranger_signing_key = _vault_session(
        stranger_identity,
        email=other_email,
        password=other_password,
    )
    stranger_list = _signed_request(
        stranger_signing_key,
        stranger_vault["access_token"],
        "GET",
        "/api/v1/vaults",
    )
    assert stranger_list.status_code == 200
    assert stranger_list.json() == {"items": []}
    assert _signed_request(
        stranger_signing_key,
        stranger_vault["access_token"],
        "GET",
        f"/api/v1/vaults/{body['id_boveda']}",
    ).status_code == 404

    forged_claims = jwt.decode(
        other_owner_vault["access_token"], get_jwt_secret(), algorithms=[settings.JWT_ALGORITHM]
    )
    forged_claims["did"] = owner_device["id_dispositivo"]
    tampered_device_token = jwt.encode(
        forged_claims,
        get_jwt_secret(),
        algorithm=settings.JWT_ALGORITHM,
    )
    assert _signed_request(
        other_owner_signing_key,
        tampered_device_token,
        "GET",
        f"/api/v1/vaults/{body['id_boveda']}",
    ).status_code == 401

    bound_to_another_device = _creation(owner_device)
    assert _signed_request(
        other_owner_signing_key,
        other_owner_vault["access_token"],
        "POST",
        "/api/v1/vaults",
        bound_to_another_device,
        retry_key="vault-envelope-device-tamper-0001",
    ).status_code == 403

    revoked = client.delete(
        f"/api/v1/devices/{owner_device['id_dispositivo']}",
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )
    assert revoked.status_code == 200, revoked.text
    assert _signed_request(
        owner_signing_key,
        vault["access_token"],
        "GET",
        "/api/v1/vaults",
    ).status_code == 401


@pytest.mark.skipif(
    os.getenv("CU06_TEST_POSTGRES") != "1",
    reason="Concurrent idempotency relies on PostgreSQL transaction semantics.",
)
def test_postgres_concurrent_vault_retries_create_one_complete_record():
    identity = new_device_identity()
    vault, _, device, vault_signing_key = _vault_session(identity)
    body = _creation(device)
    retry_key = "vault-concurrent-retry-0001"

    def create_from_independent_client():
        with TestClient(app) as independent_client:
            return _signed_request(
                vault_signing_key,
                vault["access_token"],
                "POST",
                "/api/v1/vaults",
                body,
                retry_key=retry_key,
                http_client=independent_client,
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = list(pool.map(lambda _: create_from_independent_client(), range(2)))

    assert first.status_code == second.status_code == 201
    assert first.json() == second.json()

    db = SessionLocal()
    try:
        vault_id = uuid.UUID(body["id_boveda"])
        assert db.scalar(select(func.count()).select_from(Boveda).where(Boveda.id_boveda == vault_id)) == 1
        assert db.scalar(
            select(func.count()).select_from(MembresiaBoveda).where(MembresiaBoveda.id_boveda == vault_id)
        ) == 1
        assert db.scalar(
            select(func.count()).select_from(ClaveEnvuelta).where(ClaveEnvuelta.id_boveda == vault_id)
        ) == 1
        assert db.scalar(
            select(func.count())
            .select_from(EventoAuditoria)
            .where(
                EventoAuditoria.accion == "CREAR_BOVEDA",
                EventoAuditoria.recurso_id == body["id_boveda"],
            )
        ) == 1
    finally:
        db.close()


def test_cu07_delivers_only_the_authorized_envelope_and_audits_the_delivery():
    identity = new_device_identity()
    vault, _, device, vault_signing_key = _vault_session(identity)
    body = _creation(device)
    created = _signed_request(vault_signing_key, vault["access_token"], "POST", "/api/v1/vaults", body)
    assert created.status_code == 201

    listed = _signed_request(vault_signing_key, vault["access_token"], "GET", "/api/v1/vaults")
    assert listed.status_code == 200, listed.text
    assert listed.json()["items"] == [
        {
            "id_boveda": body["id_boveda"],
            "estado": "ACTIVA",
            "rol_usuario": "PROPIETARIO",
            "version_criptografica": 1,
            "fecha_creacion": listed.json()["items"][0]["fecha_creacion"],
        }
    ]

    delivered = _signed_request(
        vault_signing_key,
        vault["access_token"],
        "GET",
        f"/api/v1/vaults/{body['id_boveda']}",
    )
    assert delivered.status_code == 200, delivered.text
    response = delivered.json()
    assert response["clave_envuelta"] == body["clave_envuelta"]
    assert "password_maestra" not in response

    db = SessionLocal()
    try:
        event = db.scalars(
            select(EventoAuditoria).where(
                EventoAuditoria.accion == "ENTREGAR_SOBRE_BOVEDA",
                EventoAuditoria.recurso_id == body["id_boveda"],
                EventoAuditoria.id_usuario == uuid.UUID(device["id_usuario"]),
                EventoAuditoria.id_dispositivo == uuid.UUID(device["id_dispositivo"]),
            )
        ).first()
        assert event is not None
        assert event.resultado == "EXITO"
        assert event.detalles == {"version_criptografica": 1, "version_clave": 1}
    finally:
        db.close()


@pytest.mark.parametrize(
    ("invalid_state", "expected_status"),
    [
        ("membership", 404),
        ("envelope", 404),
        ("security_version", 401),
        ("mfa", 403),
        ("permission", 403),
    ],
)
def test_cu07_envelope_delivery_rechecks_current_server_authorization(
    invalid_state, expected_status
):
    identity = new_device_identity()
    vault, _, device_data, vault_signing_key = _vault_session(identity)
    body = _creation(device_data)
    assert _signed_request(
        vault_signing_key, vault["access_token"], "POST", "/api/v1/vaults", body
    ).status_code == 201

    db = SessionLocal()
    try:
        user = db.get(Usuario, uuid.UUID(device_data["id_usuario"]))
        device = db.get(Dispositivo, uuid.UUID(device_data["id_dispositivo"]))
        assert user is not None and device is not None
        if invalid_state == "membership":
            membership = db.get(
                MembresiaBoveda,
                {"id_boveda": uuid.UUID(body["id_boveda"]), "id_usuario": user.id_usuario},
            )
            assert membership is not None
            membership.estado = "REVOCADA"
        elif invalid_state == "envelope":
            envelope = db.scalars(
                select(ClaveEnvuelta).where(
                    ClaveEnvuelta.id_boveda == uuid.UUID(body["id_boveda"]),
                    ClaveEnvuelta.id_dispositivo == device.id_dispositivo,
                )
            ).first()
            assert envelope is not None
            envelope.estado = "REVOCADA"
        elif invalid_state == "security_version":
            user.version_seguridad += 1
        elif invalid_state == "mfa":
            session = db.scalars(
                select(Sesion).where(Sesion.id_dispositivo == device.id_dispositivo)
            ).first()
            assert session is not None
            session.mfa_verificado_en = datetime.now(timezone.utc) - timedelta(
                minutes=settings.MFA_VAULT_MAX_AGE_MINUTES + 1
            )
        else:
            user.roles = []
        db.commit()
    finally:
        db.close()

    response = _signed_request(
        vault_signing_key,
        vault["access_token"],
        "GET",
        f"/api/v1/vaults/{body['id_boveda']}",
    )
    assert response.status_code == expected_status


def test_cu07_rejects_tampered_signatures_and_master_password_fields():
    identity = new_device_identity()
    vault, _, device, vault_signing_key = _vault_session(identity)
    body = _creation(device)
    body["password_maestra"] = "must-not-be-accepted"
    assert _signed_request(
        vault_signing_key,
        vault["access_token"],
        "POST",
        "/api/v1/vaults",
        body,
        retry_key="vault-no-master-password-0001",
    ).status_code == 422

    valid = _creation(device)
    assert _signed_request(
        vault_signing_key, vault["access_token"], "POST", "/api/v1/vaults", valid
    ).status_code == 201
    tampered = _signed_request(
        Ed25519PrivateKey.generate(),
        vault["access_token"],
        "GET",
        f"/api/v1/vaults/{valid['id_boveda']}",
    )
    assert tampered.status_code == 401


def test_cu07_does_not_deliver_an_envelope_when_its_audit_record_fails():
    identity = new_device_identity()
    vault, _, device, vault_signing_key = _vault_session(identity)
    body = _creation(device)
    assert _signed_request(
        vault_signing_key, vault["access_token"], "POST", "/api/v1/vaults", body
    ).status_code == 201

    def reject_audit_insert(_mapper, _connection, _target):
        raise RuntimeError("simulated envelope delivery audit failure")

    event.listen(EventoAuditoria, "before_insert", reject_audit_insert)
    try:
        with pytest.raises(RuntimeError, match="simulated envelope delivery audit failure"):
            _signed_request(
                vault_signing_key,
                vault["access_token"],
                "GET",
                f"/api/v1/vaults/{body['id_boveda']}",
            )
    finally:
        event.remove(EventoAuditoria, "before_insert", reject_audit_insert)

    db = SessionLocal()
    try:
        assert db.scalar(
            select(func.count())
            .select_from(EventoAuditoria)
            .where(
                EventoAuditoria.accion == "ENTREGAR_SOBRE_BOVEDA",
                EventoAuditoria.id_dispositivo == uuid.UUID(device["id_dispositivo"]),
            )
        ) == 0
    finally:
        db.close()
