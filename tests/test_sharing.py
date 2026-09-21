import base64
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core.database import SessionLocal
from app.core.security import get_password_hash
from app.models.auth import Dispositivo, EventoAuditoria, Usuario
from app.models.vault import AccesoCompartido, SobreAccesoCompartido
from app.services.sharing_service import SharingService
from tests.helpers.device_identity import new_device_identity
from tests.test_vault import _creation, _signed_request, _vault_session


def _recipient():
    identity = new_device_identity()
    db = SessionLocal()
    try:
        user = Usuario(id_usuario=uuid.uuid4(), nombre="Recipient", correo=f"recipient-{uuid.uuid4().hex}@example.test", password_hash=get_password_hash("not-used"), estado="ACTIVO")
        device = Dispositivo(id_dispositivo=uuid.uuid4(), id_usuario=user.id_usuario, identificador_seguro=identity.installation_id, public_key=identity.public_key, clave_firma_boveda=identity.public_key, huella_clave_publica=hashlib.sha256(identity.public_key.encode()).hexdigest(), estado="TRUSTED", es_confiable=True)
        db.add_all([user, device])
        db.commit()
        return user.correo, device.id_dispositivo
    finally:
        db.close()


def _envelope(device_id):
    encoded = base64.b64encode(b"opaque-recipient-envelope").decode()
    return {"id_dispositivo_destinatario": str(device_id), "algoritmo": "X25519-AES-256-GCM", "ciphertext": encoded, "nonce": base64.b64encode(b"nonce").decode(), "tag": base64.b64encode(b"tag").decode()}


def test_share_persists_opaque_envelope_and_revoke_is_immediate():
    identity = new_device_identity()
    vault_session, _, device, signing_key = _vault_session(identity)
    vault = _signed_request(signing_key, vault_session["access_token"], "POST", "/api/v1/vaults", _creation(device))
    assert vault.status_code == 201, vault.text
    recipient_email, recipient_device_id = _recipient()
    response = _signed_request(signing_key, vault_session["access_token"], "POST", "/api/v1/shares", {"correo_destinatario": recipient_email, "id_boveda": vault.json()["id_boveda"], "sobres": [_envelope(recipient_device_id)]}, retry_key="share-create-retry-0001")
    assert response.status_code == 201, response.text
    grant_id = response.json()["id_acceso_compartido"]
    db = SessionLocal()
    try:
        grant = db.get(AccesoCompartido, uuid.UUID(grant_id))
        envelope = db.scalar(select(SobreAccesoCompartido).where(SobreAccesoCompartido.id_acceso_compartido == grant.id_acceso_compartido))
        assert grant.id_boveda is not None and grant.id_archivo is None
        assert envelope.ciphertext == _envelope(recipient_device_id)["ciphertext"]
        assert "plaintext" not in str(db.scalars(select(EventoAuditoria).where(EventoAuditoria.accion == "COMPARTIR_ACCESO_CIFRADO")).one().detalles).lower()
    finally:
        db.close()
    revoked = _signed_request(signing_key, vault_session["access_token"], "POST", f"/api/v1/shares/{grant_id}/revoke", {"motivo": "test"})
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["estado"] == "REVOCADO"
    db = SessionLocal()
    try:
        assert db.get(AccesoCompartido, uuid.UUID(grant_id)).estado == "REVOCADO"
        assert db.scalar(select(SobreAccesoCompartido.estado).where(SobreAccesoCompartido.id_acceso_compartido == uuid.UUID(grant_id))) == "REVOCADO"
    finally:
        db.close()


def test_share_rejects_untrusted_recipient_device_and_expired_access():
    identity = new_device_identity()
    vault_session, _, device, signing_key = _vault_session(identity)
    vault = _signed_request(signing_key, vault_session["access_token"], "POST", "/api/v1/vaults", _creation(device))
    recipient_email, recipient_device_id = _recipient()
    db = SessionLocal(); recipient = db.scalar(select(Usuario).where(Usuario.correo == recipient_email)); recipient_device = db.get(Dispositivo, recipient_device_id); recipient_device.estado = "PENDING"; db.commit(); db.close()
    rejected = _signed_request(signing_key, vault_session["access_token"], "POST", "/api/v1/shares", {"correo_destinatario": recipient_email, "id_boveda": vault.json()["id_boveda"], "sobres": [_envelope(recipient_device_id)]}, retry_key="share-create-retry-0002")
    assert rejected.status_code == 422
    db = SessionLocal()
    try:
        recipient = db.scalar(select(Usuario).where(Usuario.correo == recipient_email))
        recipient_device = db.get(Dispositivo, recipient_device_id)
        recipient_device.estado = "TRUSTED"; db.commit()
        service = SharingService(db)
        assert service.repo.active_recipient_grant(recipient.id_usuario, recipient_device.id_dispositivo, uuid.UUID(vault.json()["id_boveda"])) is None
    finally:
        db.close()
