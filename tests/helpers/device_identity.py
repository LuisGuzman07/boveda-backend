import base64
from dataclasses import dataclass
from datetime import datetime
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.services.device_identity_service import challenge_transcript


@dataclass
class DeviceIdentity:
    installation_id: str
    private_key: Ed25519PrivateKey
    public_key: str


def new_device_identity() -> DeviceIdentity:
    private_key = Ed25519PrivateKey.generate()
    return DeviceIdentity(
        installation_id=str(uuid.uuid4()),
        private_key=private_key,
        public_key=base64.b64encode(
            private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii"),
    )


def device_payload(
    identity: DeviceIdentity,
    name: str = "Pytest device",
    vault_public_key: str | None = None,
) -> dict:
    payload = {
        "nombre": name,
        "tipo": "MOVIL",
        "sistema_operativo": "pytest",
        "identificador_seguro": identity.installation_id,
        "public_key": identity.public_key,
    }
    if vault_public_key:
        payload["vault_public_key"] = vault_public_key
    return payload


def login_with_device(
    client,
    email: str,
    password: str,
    identity: DeviceIdentity,
    vault_public_key: str | None = None,
) -> dict:
    response = client.post(
        "/api/v1/auth/login",
        json={
            "correo": email,
            "password": password,
            "dispositivo": device_payload(identity, vault_public_key=vault_public_key),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def current_device(client, access_token: str) -> dict:
    response = client.get(
        "/api/v1/devices", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, response.text
    return next(device for device in response.json()["dispositivos"] if device["es_dispositivo_actual"])


def prove_challenge(client, access_token: str, identity: DeviceIdentity, purpose: str) -> dict:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Device-Id": identity.installation_id,
    }
    issued = client.post("/api/v1/devices/challenge", headers=headers, json={"proposito": purpose})
    assert issued.status_code == 200, issued.text
    challenge = issued.json()
    device = current_device(client, access_token)
    expires_at = datetime.fromisoformat(challenge["fecha_expiracion"].replace("Z", "+00:00"))
    message = challenge_transcript(
        uuid.UUID(challenge["id_desafio"]),
        purpose,
        uuid.UUID(device["id_usuario"]),
        uuid.UUID(device["id_dispositivo"]),
        challenge["nonce"],
        expires_at,
    )
    proof = client.post(
        "/api/v1/devices/challenge/prove",
        headers=headers,
        json={
            "id_desafio": challenge["id_desafio"],
            "nonce": challenge["nonce"],
            "firma": base64.b64encode(identity.private_key.sign(message)).decode("ascii"),
        },
    )
    assert proof.status_code == 200, proof.text
    return proof.json()
