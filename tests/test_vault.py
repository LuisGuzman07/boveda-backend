import base64
import hashlib
import json
import time
import uuid

import jwt
import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import get_jwt_secret
from app.main import app
from app.models.auth import SesionBoveda, Usuario
from app.models.mfa import AutenticadorMfa
from app.models.vault import Boveda
from app.services.totp_secret_service import get_totp_secret, store_encrypted_totp_secret
from tests.helpers.device_identity import (
    current_device,
    device_payload,
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


def _mfa_login(identity, vault_signing_key):
    secret = _enable_mfa("admin@boveda.com")
    login = login_with_device(
        client,
        "admin@boveda.com",
        "Admin1234!*",
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


def _vault_session(identity):
    vault_signing_key = Ed25519PrivateKey.generate()
    login = _mfa_login(identity, vault_signing_key)
    access_token = login["access_token"]
    prove_challenge(client, access_token, identity, "DEVICE_ENROLLMENT")
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


def _signed_request(signing_key, vault_token, method, path, body=None, retry_key="vault-retry-key-0001"):
    text = json.dumps(body, separators=(",", ":")) if body is not None else ""
    payload = jwt.decode(vault_token, get_jwt_secret(), algorithms=[settings.JWT_ALGORITHM])
    timestamp = str(int(time.time()))
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
    return client.request(
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
    plain_login = login_with_device(client, "admin@boveda.com", "Admin1234!*", identity)
    access = plain_login["access_token"]
    prove_challenge(client, access, identity, "DEVICE_ENROLLMENT")
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
