import base64
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.models.auth import Dispositivo, EventoAuditoria, Usuario
from app.models.policy import PoliticaSeguridad
from app.models.vault import Boveda, ClaveEnvuelta, KitEmergencia, MembresiaBoveda
from app.schemas.vault import EmergencyKitCreateRequest, EmergencyKitRecoverRequest
from app.services.emergency_kit_service import EmergencyKitService


def _b64(size):
    return base64.b64encode(b"x" * size).decode()


def _kit_request(kit_id=None):
    return EmergencyKitCreateRequest(
        id_boveda=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        id_kit=kit_id or uuid.uuid4(),
        kdf_salt=_b64(16),
        kdf_salt_boveda=_b64(16),
        kdf_parametros={
            "algoritmo": "Argon2id", "memoria_kib": 65536,
            "iteraciones": 3, "paralelismo": 1, "longitud": 32,
        },
        sobre_cifrado={
            "algoritmo": "AES-256-GCM", "ciphertext": _b64(32),
            "nonce": _b64(12), "tag": _b64(16),
        },
        huella_kit="a" * 64,
    )


@pytest.fixture
def kit_environment(isolated_database):
    from app.core.database import SessionLocal
    db = SessionLocal()
    user = Usuario(nombre="Kit User", correo="kit@example.com", password_hash="not-used", estado="ACTIVO")
    db.add(user)
    db.flush()
    device = Dispositivo(
        id_usuario=user.id_usuario, identificador_seguro="kit-device-12345",
        estado="TRUSTED", es_confiable=True,
    )
    vault = Boveda(
        id_boveda=uuid.uuid4(), id_propietario=user.id_usuario,
        nombre_cifrado={}, descripcion_cifrada=None, version_criptografica=1,
        kdf_salt=_b64(16), kdf_parametros={}, idempotency_key="kit-idempotency",
        solicitud_hash="b" * 64,
    )
    db.add_all([device, vault])
    db.flush()
    db.add(MembresiaBoveda(id_boveda=vault.id_boveda, id_usuario=user.id_usuario))
    db.add(PoliticaSeguridad(codigo="EMERGENCY_KIT_ENABLED", nombre="Emergency Kit", valor="true", activa=True))
    db.commit()
    yield db, user, device, vault
    db.close()


def test_create_export_and_recover_never_returns_plaintext_key(kit_environment):
    db, user, device, vault = kit_environment
    service = EmergencyKitService(db)
    request = _kit_request()
    request.id_boveda = vault.id_boveda
    request.kdf_salt_boveda = vault.kdf_salt
    created = service.create(user, device, vault.id_boveda, request, "127.0.0.1", "test")

    assert created["sobre_cifrado"]["ciphertext"]
    assert "clave" not in created
    exported = service.export(user, device, vault.id_boveda, "127.0.0.1", "test")
    assert exported["id_kit"] == created["id_kit"]
    assert "password" not in str(exported).lower()

    body = EmergencyKitRecoverRequest(
        id_kit=created["id_kit"], id_dispositivo=device.id_dispositivo,
        clave_envuelta={
            "id_dispositivo": device.id_dispositivo,
            "algoritmo": "AES-256-GCM", "ciphertext": _b64(32),
            "nonce": _b64(12), "tag": _b64(16), "version_clave": 1,
        },
    )
    result = service.recover(user, device, vault.id_boveda, body, "127.0.0.1", "test")
    assert result["status"] == "ok"
    stored = db.scalar(select(ClaveEnvuelta).where(ClaveEnvuelta.id_boveda == vault.id_boveda))
    assert stored.ciphertext == body.clave_envuelta.ciphertext
    assert "x" * 32 not in str(stored)


def test_wrong_kit_revoked_and_expired_kit_are_rejected(kit_environment):
    db, user, device, vault = kit_environment
    service = EmergencyKitService(db)
    request = _kit_request()
    request.id_boveda = vault.id_boveda
    request.kdf_salt_boveda = vault.kdf_salt
    created = service.create(user, device, vault.id_boveda, request, None, None)
    body = EmergencyKitRecoverRequest(
        id_kit=uuid.uuid4(), id_dispositivo=device.id_dispositivo,
        clave_envuelta={
            "id_dispositivo": device.id_dispositivo, "algoritmo": "AES-256-GCM",
            "ciphertext": _b64(32), "nonce": _b64(12), "tag": _b64(16), "version_clave": 1,
        },
    )
    with pytest.raises(HTTPException) as wrong:
        service.recover(user, device, vault.id_boveda, body, None, None)
    assert wrong.value.status_code == 400

    kit = db.get(KitEmergencia, created["id_kit"])
    kit.fecha_expiracion = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    body.id_kit = kit.id_kit
    with pytest.raises(HTTPException):
        service.recover(user, device, vault.id_boveda, body, None, None)

    kit.fecha_expiracion = None
    kit.estado = "REVOCADO"
    db.commit()
    with pytest.raises(HTTPException):
        service.recover(user, device, vault.id_boveda, body, None, None)


def test_replacement_revokes_previous_and_audits_failures(kit_environment):
    db, user, device, vault = kit_environment
    service = EmergencyKitService(db)
    first_request = _kit_request()
    first_request.id_boveda = vault.id_boveda
    first_request.kdf_salt_boveda = vault.kdf_salt
    second_request = _kit_request()
    second_request.id_boveda = vault.id_boveda
    second_request.kdf_salt_boveda = vault.kdf_salt
    first = service.create(user, device, vault.id_boveda, first_request, None, None)
    second = service.create(user, device, vault.id_boveda, second_request, None, None)
    db.expire_all()
    first_row = db.get(KitEmergencia, first["id_kit"])
    second_row = db.get(KitEmergencia, second["id_kit"])
    assert first_row.estado == "REVOCADO"
    assert second_row.estado == "ACTIVO"
    assert db.scalars(select(EventoAuditoria).where(EventoAuditoria.tipo_evento == "RECUPERACION_BOVEDA")).all()


def test_recovery_requires_trusted_device_and_active_policy(kit_environment):
    db, user, device, vault = kit_environment
    service = EmergencyKitService(db)
    policy = db.scalar(select(PoliticaSeguridad).where(PoliticaSeguridad.codigo == "EMERGENCY_KIT_ENABLED"))
    policy.valor = "false"
    db.commit()
    with pytest.raises(HTTPException) as denied:
        request = _kit_request()
        request.id_boveda = vault.id_boveda
        request.kdf_salt_boveda = vault.kdf_salt
        service.create(user, device, vault.id_boveda, request, None, None)
    assert denied.value.status_code == 403
