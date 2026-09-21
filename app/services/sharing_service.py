import hashlib
import json
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from app.models.auth import EventoAuditoria
from app.models.vault import AccesoCompartido, SobreAccesoCompartido
from app.repositories.sharing_repository import SharingRepository


class SharingService:
    def __init__(self, db):
        self.db = db
        self.repo = SharingRepository(db)

    def create(self, user, device, body, retry_key, ip=None):
        self._require_share(user, device, "FALLO_AUTORIZACION_COMPARTIR", ip)
        data = body.model_dump(mode="json")
        fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        existing = self.repo.retry(user.id_usuario, retry_key)
        if existing:
            if existing.solicitud_hash != fingerprint:
                raise HTTPException(409, "Idempotency-Key ya fue utilizada con otros datos.")
            return self.serialize(existing, self.repo.envelopes(existing.id_acceso_compartido))
        recipient = self.repo.recipient(body.correo_destinatario)
        if not recipient or recipient.id_usuario == user.id_usuario:
            self._audit(user, device, "FALLO_DESTINATARIO_COMPARTIR", None, ip)
            raise HTTPException(422, "El destinatario debe ser otro usuario activo.")
        if not self.repo.owner_of_scope(user.id_usuario, body.id_boveda, body.id_archivo):
            self._audit(user, device, "FALLO_ALCANCE_COMPARTIR", body.id_boveda or body.id_archivo, ip)
            raise HTTPException(403, "Solo el propietario puede compartir este recurso.")
        devices = self.repo.trusted_devices(recipient.id_usuario, [item.id_dispositivo_destinatario for item in body.sobres])
        if len(devices) != len(body.sobres):
            self._audit(user, device, "FALLO_DISPOSITIVO_DESTINATARIO", body.id_boveda or body.id_archivo, ip)
            raise HTTPException(422, "Cada sobre debe estar dirigido a un dispositivo TRUSTED del destinatario.")
        now = datetime.now(timezone.utc)
        if body.expira_en and body.expira_en <= now:
            raise HTTPException(422, "La expiración debe estar en el futuro.")
        grant = AccesoCompartido(id_boveda=body.id_boveda, id_archivo=body.id_archivo, id_destinatario=recipient.id_usuario, id_otorgante=user.id_usuario, permiso=body.permiso, inicia_en=body.inicia_en or now, expira_en=body.expira_en, epoca_clave=body.epoca_clave, version_clave=body.version_clave, idempotency_key=retry_key, solicitud_hash=fingerprint)
        fingerprints = {item.id_dispositivo: item.huella_clave_publica for item in devices}
        try:
            self.db.add(grant)
            self.db.flush()
            envelopes = [SobreAccesoCompartido(id_acceso_compartido=grant.id_acceso_compartido, id_dispositivo_destinatario=item.id_dispositivo_destinatario, algoritmo=item.algoritmo, ciphertext=item.ciphertext, nonce=item.nonce, tag=item.tag, huella_identidad_destinatario=fingerprints[item.id_dispositivo_destinatario], epoca_clave=body.epoca_clave, version_clave=body.version_clave) for item in body.sobres]
            self.db.add_all(envelopes + [self._event(user, device, "COMPARTIR_ACCESO_CIFRADO", "EXITO", grant.id_acceso_compartido, ip, {"alcance": "BOVEDA" if body.id_boveda else "ARCHIVO", "destinatario": str(recipient.id_usuario), "sobres": len(envelopes), "epoca_clave": body.epoca_clave})])
            self.db.commit()
        except IntegrityError as error:
            self.db.rollback()
            raise HTTPException(409, "El acceso compartido no pudo registrarse.") from error
        return self.serialize(grant, envelopes)

    def list_owned(self, user, device, vault_id=None):
        self._require_share(user, device, "FALLO_AUTORIZACION_LISTAR_COMPARTIDOS", None)
        return [self.serialize(grant, self.repo.envelopes(grant.id_acceso_compartido)) for grant in self.repo.list_owned(user.id_usuario, vault_id)]

    def get_owned(self, user, device, grant_id):
        self._require_share(user, device, "FALLO_AUTORIZACION_DETALLE_COMPARTIDO", None)
        grant = self.repo.get_owned(grant_id, user.id_usuario)
        if not grant:
            raise HTTPException(404, "Acceso compartido no encontrado.")
        return self.serialize(grant, self.repo.envelopes(grant.id_acceso_compartido))

    def revoke(self, user, device, grant_id, reason, ip=None):
        self._require_share(user, device, "FALLO_AUTORIZACION_REVOCAR_COMPARTIDO", ip)
        grant = self.repo.get_owned(grant_id, user.id_usuario)
        if not grant:
            raise HTTPException(404, "Acceso compartido no encontrado.")
        if grant.estado == "REVOCADO":
            return {"id_acceso_compartido": grant.id_acceso_compartido, "estado": grant.estado, "idempotente": True, "limitacion": "No elimina ciphertext ni plaintext que el destinatario haya obtenido fuera de línea."}
        now = datetime.now(timezone.utc)
        grant.estado, grant.revocado_en, grant.revocado_por, grant.motivo_revocacion = "REVOCADO", now, user.id_usuario, reason or "REVOCADO_POR_OTORGANTE"
        for envelope in self.repo.envelopes(grant.id_acceso_compartido):
            envelope.estado, envelope.revocado_en = "REVOCADO", now
        revoked = self.repo.revoke_recipient_sessions(grant.id_destinatario, "ACCESO_COMPARTIDO_REVOCADO")
        self.db.add(self._event(user, device, "REVOCAR_ACCESO_COMPARTIDO", "EXITO", grant.id_acceso_compartido, ip, {"sesiones_destinatario_revocadas": revoked, "epoca_clave_siguiente": grant.epoca_clave + 1, "rotacion_prospectiva_requerida": True}))
        self.db.commit()
        return {"id_acceso_compartido": grant.id_acceso_compartido, "estado": grant.estado, "idempotente": False, "epoca_clave_siguiente": grant.epoca_clave + 1, "limitacion": "No elimina ciphertext ni plaintext que el destinatario haya obtenido fuera de línea."}

    def recipient_grant(self, user, device, vault_id, file_id=None):
        return self.repo.active_recipient_grant(user.id_usuario, device.id_dispositivo, vault_id, file_id)

    def _require_share(self, user, device, action, ip):
        permissions = {permission.codigo for role in user.roles for permission in role.permisos}
        if "files:share" not in permissions:
            self._audit(user, device, action, None, ip)
            raise HTTPException(403, "No tienes permiso para compartir o revocar accesos.")

    def _audit(self, user, device, action, resource_id, ip):
        self.db.add(self._event(user, device, action, "FALLO", resource_id, ip, {}))
        self.db.commit()

    @staticmethod
    def _event(user, device, action, result, resource_id, ip, details):
        return EventoAuditoria(id_usuario=user.id_usuario, id_dispositivo=device.id_dispositivo, accion=action, tipo_evento="ACCESO_COMPARTIDO", resultado=result, recurso_id=str(resource_id) if resource_id else None, recurso_tipo="ACCESO_COMPARTIDO", direccion_ip=ip, detalles=details)

    @staticmethod
    def serialize(grant, envelopes):
        return {"id_acceso_compartido": grant.id_acceso_compartido, "id_boveda": grant.id_boveda, "id_archivo": grant.id_archivo, "id_destinatario": grant.id_destinatario, "permiso": grant.permiso, "inicia_en": grant.inicia_en, "expira_en": grant.expira_en, "estado": grant.estado, "epoca_clave": grant.epoca_clave, "version_clave": grant.version_clave, "sobres": [{"id_dispositivo_destinatario": item.id_dispositivo_destinatario, "algoritmo": item.algoritmo, "ciphertext": item.ciphertext, "nonce": item.nonce, "tag": item.tag} for item in envelopes]}
