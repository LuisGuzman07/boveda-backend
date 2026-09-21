import hashlib
import json
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from app.models.auth import EventoAuditoria
from app.models.vault import Boveda, ClaveEnvuelta, MembresiaBoveda
from app.repositories.vault_repository import VaultRepository
from app.services.sharing_service import SharingService


class VaultService:
    def __init__(self, db):
        self.db = db
        self.repo = VaultRepository(db)

    def serialize(self, vault, key):
        return {"id_boveda": str(vault.id_boveda), "estado": vault.estado, "rol_usuario": "PROPIETARIO", "version_criptografica": vault.version_criptografica, "fecha_creacion": vault.fecha_creacion, "nombre_cifrado": vault.nombre_cifrado, "descripcion_cifrada": vault.descripcion_cifrada, "kdf_salt": vault.kdf_salt, "kdf_parametros": vault.kdf_parametros, "clave_envuelta": {"id_dispositivo": str(key.id_dispositivo), "algoritmo": key.algoritmo, "ciphertext": key.ciphertext, "nonce": key.nonce, "tag": key.tag, "version_clave": key.version_clave}}

    def list_vaults(self, user, device):
        owned = [self.serialize(vault, key) for vault, key in self.repo.get_owned(user.id_usuario, device.id_dispositivo)]
        shared = []
        from app.models.vault import AccesoCompartido, Boveda
        from sqlalchemy import select
        for grant in self.db.scalars(select(AccesoCompartido).where(AccesoCompartido.id_destinatario == user.id_usuario, AccesoCompartido.id_boveda.is_not(None))).all():
            active = SharingService(self.db).recipient_grant(user, device, grant.id_boveda)
            if active and active.id_acceso_compartido == grant.id_acceso_compartido:
                vault = self.db.get(Boveda, grant.id_boveda)
                envelope = SharingService(self.db).repo.envelopes(grant.id_acceso_compartido, device.id_dispositivo)[0]
                shared.append({"id_boveda": str(vault.id_boveda), "estado": vault.estado, "rol_usuario": "COMPARTIDO", "version_criptografica": vault.version_criptografica, "fecha_creacion": vault.fecha_creacion, "nombre_cifrado": vault.nombre_cifrado, "descripcion_cifrada": vault.descripcion_cifrada, "kdf_salt": vault.kdf_salt, "kdf_parametros": vault.kdf_parametros, "clave_envuelta": {"id_dispositivo": str(device.id_dispositivo), "algoritmo": envelope.algoritmo, "ciphertext": envelope.ciphertext, "nonce": envelope.nonce, "tag": envelope.tag, "version_clave": envelope.version_clave}})
        return owned + shared

    def get_vault(self, user, device, vault_id):
        rows = self.repo.get_owned(user.id_usuario, device.id_dispositivo, vault_id)
        if rows:
            return self.serialize(*rows[0])
        grant = SharingService(self.db).recipient_grant(user, device, vault_id)
        if not grant:
            raise HTTPException(404, "Bóveda no disponible para este dispositivo.")
        return next(item for item in self.list_vaults(user, device) if item["id_boveda"] == str(vault_id))

    def create(self, user, device, body, retry_key, ip=None):
        permissions = {permission.codigo for role in user.roles for permission in role.permisos}
        if "vaults:create" not in permissions:
            raise HTTPException(403, "No tienes permiso para crear bóvedas.")
        if body.clave_envuelta.id_dispositivo != device.id_dispositivo:
            raise HTTPException(403, "La clave debe estar dirigida al dispositivo autenticado.")
        data = body.model_dump(mode="json")
        fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        existing = self.repo.find_retry(user.id_usuario, retry_key)
        if existing:
            if existing.solicitud_hash != fingerprint:
                raise HTTPException(409, "Idempotency-Key ya fue utilizada con otros datos.")
            return self.get_vault(user, device, existing.id_boveda)
        vault = Boveda(id_boveda=body.id_boveda, id_propietario=user.id_usuario, nombre_cifrado=data["nombre_cifrado"], descripcion_cifrada=data["descripcion_cifrada"], version_criptografica=1, kdf_salt=body.kdf_salt, kdf_parametros=data["kdf_parametros"], idempotency_key=retry_key, solicitud_hash=fingerprint)
        key_data = data["clave_envuelta"].copy()
        key_data["id_dispositivo"] = device.id_dispositivo
        key = ClaveEnvuelta(id_boveda=vault.id_boveda, id_usuario=user.id_usuario, **key_data)
        try:
            self.db.add(vault)
            self.db.flush()
            self.db.add_all([MembresiaBoveda(id_boveda=vault.id_boveda, id_usuario=user.id_usuario), key, EventoAuditoria(id_usuario=user.id_usuario, id_dispositivo=device.id_dispositivo, accion="CREAR_BOVEDA", tipo_evento="BOVEDA", resultado="EXITO", recurso_id=str(vault.id_boveda), recurso_tipo="BOVEDA", direccion_ip=ip, detalles={"version_criptografica": 1})])
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            existing = self.repo.find_retry(user.id_usuario, retry_key)
            if existing and existing.solicitud_hash == fingerprint:
                return self.get_vault(user, device, existing.id_boveda)
            raise HTTPException(409, "Bóveda o reintento ya registrado.")
        except Exception:
            self.db.rollback()
            raise
        self.db.refresh(vault)
        return self.serialize(vault, key)
