import base64
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
import jwt
import pyotp
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from app.core.config import settings
from app.core.database import Base, get_db
from app.core.security import create_access_token, create_refresh_token, get_jwt_secret, get_password_hash, hash_token
from app.main import app
from app.models.auth import Dispositivo, EventoAuditoria, Permiso, Rol, Sesion, Usuario
from app.models.mfa import AutenticadorMfa
from app.models.vault import Boveda, ClaveEnvuelta, MembresiaBoveda


@pytest.fixture
def vault_engine():
    if os.getenv("CU06_TEST_POSTGRES") != "1":
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        try:
            yield engine
        finally:
            engine.dispose()
        return
    schema = "test_cu06_" + uuid.uuid4().hex
    admin = create_engine(settings.DATABASE_URL)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(settings.DATABASE_URL, connect_args={"options": f"-csearch_path={schema}"})
    try:
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.fixture
def environment(vault_engine):
    engine = vault_engine
    Base.metadata.create_all(engine)
    db = Session(engine)
    signing_key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    user = Usuario(id_usuario=uuid.uuid4(), nombre="CU06", correo="cu06@example.com", password_hash="unused", roles=[Rol(nombre="Creador", permisos=[Permiso(codigo="vaults:create", nombre="Crear bóvedas")])])
    db.add(user)
    db.flush()
    device = Dispositivo(id_dispositivo=uuid.uuid4(), id_usuario=user.id_usuario, identificador_seguro="test-cu06-device", es_confiable=True, estado="ACTIVO", public_key=public_key)
    refresh = create_refresh_token(user.id_usuario)
    session = Sesion(id_sesion=uuid.uuid4(), id_usuario=user.id_usuario, id_dispositivo=device.id_dispositivo, refresh_token_hash=hash_token(refresh), fecha_expiracion=datetime.now(timezone.utc) + timedelta(days=1))
    secret = pyotp.random_base32()
    db.add_all([device, session, AutenticadorMfa(id_usuario=user.id_usuario, tipo="TOTP", secreto_cifrado=secret, estado="ACTIVO")])
    db.commit()
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app)
    response = client.post("/api/v1/vaults/session", headers={"Authorization": "Bearer " + create_access_token(user.id_usuario)}, json={"refresh_token": refresh, "code": pyotp.TOTP(secret).now(), "public_key": public_key})
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    yield client, db, user, device, session, signing_key, token
    app.dependency_overrides.pop(get_db, None)
    db.close()


def envelope(length=32):
    return {"algoritmo": "AES-256-GCM", "ciphertext": base64.b64encode(bytes(length)).decode(), "nonce": base64.b64encode(bytes(12)).decode(), "tag": base64.b64encode(bytes(16)).decode()}


def creation(device):
    return {"id_boveda": str(uuid.uuid4()), "nombre_cifrado": envelope(), "descripcion_cifrada": None, "version_criptografica": 1, "kdf_salt": base64.b64encode(bytes(16)).decode(), "kdf_parametros": {"algoritmo": "Argon2id", "memoria_kib": 65536, "iteraciones": 3, "paralelismo": 1, "longitud": 32}, "clave_envuelta": {**envelope(200), "id_dispositivo": str(device.id_dispositivo), "version_clave": 1}}


def signed_request(environment, method, path, body=None, retry_key="cu06-retry-key-0001", timestamp=None):
    client, _, _, _, _, signing_key, token = environment
    text = json.dumps(body, separators=(",", ":")) if body is not None else ""
    timestamp = str(timestamp if timestamp is not None else int(time.time()))
    payload = jwt.decode(token, get_jwt_secret(), algorithms=[settings.JWT_ALGORITHM])
    message = "\n".join([payload["jti"], timestamp, method, path, retry_key, hashlib.sha256(text.encode()).hexdigest()]).encode()
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json", "Idempotency-Key": retry_key, "X-Vault-Timestamp": timestamp, "X-Vault-Signature": base64.b64encode(signing_key.sign(message)).decode()}
    return client.request(method, path, headers=headers, content=text)


def test_creation_retry_and_retrieval(environment):
    _, db, user, device, *_ = environment
    body = creation(device)
    response = signed_request(environment, "POST", "/api/v1/vaults", body)
    assert response.status_code == 201, response.text
    retry = signed_request(environment, "POST", "/api/v1/vaults", body)
    assert retry.json() == response.json()
    assert db.scalar(select(func.count()).select_from(Boveda)) == 1
    assert db.scalar(select(func.count()).select_from(MembresiaBoveda)) == 1
    assert db.scalar(select(func.count()).select_from(ClaveEnvuelta)) == 1
    assert db.scalar(select(func.count()).select_from(EventoAuditoria)) == 1
    assert db.scalar(select(MembresiaBoveda)).rol_boveda == "PROPIETARIO"
    event_record = db.scalar(select(EventoAuditoria))
    assert event_record.accion == "CREAR_BOVEDA"
    assert event_record.detalles == {"version_criptografica": 1}
    retrieved = signed_request(environment, "GET", "/api/v1/vaults/" + body["id_boveda"])
    assert retrieved.status_code == 200
    assert retrieved.json()["clave_envuelta"] == body["clave_envuelta"]
    assert len(signed_request(environment, "GET", "/api/v1/vaults").json()["items"]) == 1
    body["nombre_cifrado"] = envelope(48)
    assert signed_request(environment, "POST", "/api/v1/vaults", body).status_code == 409


def test_requires_session_and_device_signature(environment):
    client, _, _, device, *_ = environment
    body = creation(device)
    assert client.post("/api/v1/vaults", json=body, headers={"Idempotency-Key": "cu06-retry-key-0001"}).status_code == 401
    assert signed_request(environment, "POST", "/api/v1/vaults", body, timestamp=int(time.time()) - 120).status_code == 401
    assert client.get("/api/v1/vaults", headers={"Authorization": "Bearer " + environment[-1]}).status_code == 401


@pytest.mark.parametrize("revoked", ["session", "device", "trust", "user", "permission", "key"])
def test_rejects_revocation_and_missing_permission(environment, revoked):
    _, db, user, device, session, *_ = environment
    if revoked == "session":
        session.revocada = True
    elif revoked == "device":
        device.estado = "REVOCADO"
    elif revoked == "trust":
        device.es_confiable = False
    elif revoked == "user":
        user.estado = "INACTIVO"
    elif revoked == "permission":
        user.roles = []
    else:
        device.public_key = "changed"
    db.commit()
    assert signed_request(environment, "POST", "/api/v1/vaults", creation(device)).status_code in (401, 403)
    assert db.scalar(select(func.count()).select_from(Boveda)) == 0


def test_wrong_device_and_invalid_envelopes(environment):
    body = creation(environment[3])
    body["clave_envuelta"]["id_dispositivo"] = str(uuid.uuid4())
    assert signed_request(environment, "POST", "/api/v1/vaults", body).status_code == 403
    body = creation(environment[3])
    body["nombre_cifrado"]["nonce"] = base64.b64encode(bytes(8)).decode()
    assert signed_request(environment, "POST", "/api/v1/vaults", body).status_code == 422


def test_rollback_if_audit_fails(environment):
    client, db, _, device, *_ = environment
    def reject_insert(mapper, connection, target):
        raise RuntimeError("simulated audit failure")
    event.listen(EventoAuditoria, "before_insert", reject_insert)
    try:
        with pytest.raises(RuntimeError, match="simulated audit failure"):
            signed_request(environment, "POST", "/api/v1/vaults", creation(device))
    finally:
        event.remove(EventoAuditoria, "before_insert", reject_insert)
    for model in (Boveda, MembresiaBoveda, ClaveEnvuelta, EventoAuditoria):
        assert db.scalar(select(func.count()).select_from(model)) == 0


def test_other_device_cannot_retrieve_envelope(environment):
    body = creation(environment[3])
    assert signed_request(environment, "POST", "/api/v1/vaults", body).status_code == 201
    from app.services.vault_service import VaultService
    from fastapi import HTTPException
    stranger = Dispositivo(id_dispositivo=uuid.uuid4())
    with pytest.raises(HTTPException) as error:
        VaultService(environment[1]).get_vault(environment[2], stranger, uuid.UUID(body["id_boveda"]))
    assert error.value.status_code == 404


def test_existing_login_mfa_device_flow_opens_vault_session(environment):
    client, db, user, device, session, *_ = environment
    db.delete(session)
    user.password_hash = get_password_hash("Cu06Test123!*")
    db.commit()
    mfa = db.scalar(select(AutenticadorMfa))
    device_info = {"identificador_seguro": device.identificador_seguro, "public_key": device.public_key, "confiar_dispositivo": True}
    login = client.post("/api/v1/auth/login", json={"correo": user.correo, "password": "Cu06Test123!*", "dispositivo": device_info})
    assert login.status_code == 200, login.text
    assert login.json()["mfa_required"] is True
    code = pyotp.TOTP(mfa.secreto_cifrado).now()
    verified = client.post("/api/v1/auth/mfa/verify-login", json={"mfa_token": login.json()["mfa_token"], "code": code, "dispositivo": device_info, "confiar_dispositivo": True})
    assert verified.status_code == 200, verified.text
    tokens = verified.json()
    scoped = client.post("/api/v1/vaults/session", headers={"Authorization": "Bearer " + tokens["access_token"]}, json={"refresh_token": tokens["refresh_token"], "code": code, "public_key": device.public_key})
    assert scoped.status_code == 200, scoped.text
    assert scoped.json()["id_dispositivo"] == str(device.id_dispositivo)
    updated = (*environment[:-1], scoped.json()["access_token"])
    assert signed_request(updated, "POST", "/api/v1/vaults", creation(device)).status_code == 201


def test_vault_session_rejects_missing_mfa_and_unregistered_key(environment):
    client, db, user, device, session, *_ = environment
    mfa = db.scalar(select(AutenticadorMfa))
    token = create_refresh_token(user.id_usuario)
    session.refresh_token_hash = hash_token(token)
    db.commit()
    headers = {"Authorization": "Bearer " + create_access_token(user.id_usuario)}
    body = {"refresh_token": token, "code": pyotp.TOTP(mfa.secreto_cifrado).now(), "public_key": base64.b64encode(bytes(32)).decode()}
    assert client.post("/api/v1/vaults/session", headers=headers, json=body).status_code == 403
    body["public_key"] = device.public_key
    mfa.estado = "INACTIVO"
    db.commit()
    assert client.post("/api/v1/vaults/session", headers=headers, json=body).status_code == 403
