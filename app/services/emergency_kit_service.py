from datetime import datetime, timedelta, timezone
import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.auth import Dispositivo, EventoAuditoria
from app.models.policy import PoliticaSeguridad
from app.models.vault import Boveda, ClaveEnvuelta, KitEmergencia, MembresiaBoveda
from app.repositories.emergency_kit_repository import EmergencyKitRepository
from app.schemas.vault import EmergencyKitCreateRequest, EmergencyKitRecoverRequest


class EmergencyKitService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = EmergencyKitRepository(db)

    def _authorize(self, user, device, vault_id: uuid.UUID) -> Boveda:
        vault = self.db.scalar(select(Boveda).join(MembresiaBoveda).where(
            Boveda.id_boveda == vault_id,
            Boveda.id_propietario == user.id_usuario,
            Boveda.estado == "ACTIVA",
            MembresiaBoveda.id_usuario == user.id_usuario,
            MembresiaBoveda.estado == "ACTIVA",
        ))
        if not vault:
            raise HTTPException(status_code=404, detail="Bóveda no disponible para recuperación.")
        policy = self.db.scalar(select(PoliticaSeguridad).where(PoliticaSeguridad.codigo == "EMERGENCY_KIT_ENABLED"))
        if not policy or not policy.activa or policy.valor.upper() not in {"1", "TRUE", "ENABLED"}:
            raise HTTPException(status_code=403, detail="La política de recuperación de emergencia está desactivada.")
        if device.estado != "TRUSTED" or not device.es_confiable:
            raise HTTPException(status_code=403, detail="El dispositivo debe estar TRUSTED y vigente.")
        return vault

    @staticmethod
    def _read(kit: KitEmergencia) -> dict:
        return {
            "id_kit": kit.id_kit,
            "id_boveda": kit.id_boveda,
            "version_kit": kit.version_kit,
            "version_criptografica": kit.version_criptografica,
            "algoritmo_kdf": kit.algoritmo_kdf,
            "kdf_salt": kit.kdf_salt,
            "kdf_salt_boveda": kit.kdf_salt_boveda,
            "kdf_parametros": kit.kdf_parametros,
            "sobre_cifrado": kit.sobre_cifrado,
            "huella_kit": kit.huella_kit,
            "estado": kit.estado,
            "fecha_expiracion": kit.fecha_expiracion.isoformat() if kit.fecha_expiracion else None,
        }

    def create(self, user, device, vault_id, body: EmergencyKitCreateRequest, ip, user_agent):
        vault = self._authorize(user, device, vault_id)
        if body.id_boveda != vault.id_boveda or body.kdf_salt_boveda != vault.kdf_salt:
            raise HTTPException(status_code=400, detail="Los metadatos del kit no corresponden a la bóveda.")
        self.repo.revoke_active(vault.id_boveda, user.id_usuario)
        previous = self.db.scalar(select(KitEmergencia.version_kit).where(KitEmergencia.id_boveda == vault.id_boveda).order_by(KitEmergencia.version_kit.desc())) or 0
        kit = KitEmergencia(
            id_kit=body.id_kit,
            id_boveda=vault.id_boveda,
            id_usuario=user.id_usuario,
            version_kit=previous + 1,
            version_criptografica=body.version_criptografica,
            algoritmo_kdf=body.kdf_parametros.algoritmo,
            kdf_salt=body.kdf_salt,
            kdf_salt_boveda=body.kdf_salt_boveda,
            kdf_parametros=body.kdf_parametros.model_dump(mode="json"),
            sobre_cifrado=body.sobre_cifrado.model_dump(mode="json"),
            huella_kit=body.huella_kit,
            fecha_expiracion=datetime.now(timezone.utc) + timedelta(days=body.expira_en_dias),
        )
        self.db.add(kit)
        self.db.add(EventoAuditoria(
            id_usuario=user.id_usuario, id_dispositivo=device.id_dispositivo,
            accion="KIT_EMERGENCIA_CREADO", tipo_evento="RECUPERACION_BOVEDA", resultado="EXITO",
            recurso_id=str(vault.id_boveda), recurso_tipo="KIT_EMERGENCIA", direccion_ip=ip,
            user_agent=user_agent, detalles={"version_kit": kit.version_kit, "huella_kit": body.huella_kit},
        ))
        self.db.commit()
        return self._read(kit)

    def export(self, user, device, vault_id, ip, user_agent):
        self._authorize(user, device, vault_id)
        kit = self.repo.active_for_vault(vault_id, user.id_usuario)
        if not kit:
            raise HTTPException(status_code=404, detail="No hay un Emergency Kit activo para esta bóveda.")
        self.db.add(EventoAuditoria(
            id_usuario=user.id_usuario, id_dispositivo=device.id_dispositivo,
            accion="KIT_EMERGENCIA_EXPORTADO", tipo_evento="RECUPERACION_BOVEDA", resultado="EXITO",
            recurso_id=str(vault_id), recurso_tipo="KIT_EMERGENCIA", direccion_ip=ip,
            user_agent=user_agent, detalles={"version_kit": kit.version_kit, "huella_kit": kit.huella_kit},
        ))
        self.db.commit()
        return self._read(kit)

    def recover(self, user, device, vault_id, body: EmergencyKitRecoverRequest, ip, user_agent):
        vault = self._authorize(user, device, vault_id)
        kit = self.repo.valid(body.id_kit, vault.id_boveda, user.id_usuario)
        if not kit:
            self._audit(user, device, vault_id, "KIT_EMERGENCIA_RECUPERACION_FALLIDA", "FALLO", ip, user_agent)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Emergency Kit inválido, revocado o expirado.")
        if body.id_dispositivo != device.id_dispositivo or body.clave_envuelta.id_dispositivo != device.id_dispositivo:
            self._audit(user, device, vault_id, "KIT_EMERGENCIA_RECUPERACION_FALLIDA", "DENEGADO", ip, user_agent)
            raise HTTPException(status_code=403, detail="La recuperación debe dirigirse al dispositivo autenticado.")
        self.db.query(ClaveEnvuelta).filter(
            ClaveEnvuelta.id_boveda == vault.id_boveda,
            ClaveEnvuelta.id_usuario == user.id_usuario,
            ClaveEnvuelta.id_dispositivo == device.id_dispositivo,
            ClaveEnvuelta.id_version_archivo.is_(None),
            ClaveEnvuelta.estado == "ACTIVA",
        ).update({"estado": "REVOCADA"}, synchronize_session=False)
        self.db.add(ClaveEnvuelta(
            id_boveda=vault.id_boveda, id_usuario=user.id_usuario,
            id_dispositivo=device.id_dispositivo,
            algoritmo=body.clave_envuelta.algoritmo,
            ciphertext=body.clave_envuelta.ciphertext,
            nonce=body.clave_envuelta.nonce,
            tag=body.clave_envuelta.tag,
            version_clave=body.clave_envuelta.version_clave,
        ))
        self._audit(user, device, vault_id, "KIT_EMERGENCIA_RECUPERADO", "EXITO", ip, user_agent, {"kit_version": kit.version_kit})
        self.db.commit()
        return {"status": "ok", "message": "La clave fue reenviada localmente al dispositivo autorizado.", "id_boveda": vault.id_boveda}

    def revoke(self, user, device, vault_id, ip, user_agent):
        vault = self._authorize(user, device, vault_id)
        kit = self.repo.active_for_vault(vault.id_boveda, user.id_usuario)
        if not kit:
            raise HTTPException(status_code=404, detail="No hay un Emergency Kit activo para esta bóveda.")
        self.repo.revoke_active(vault.id_boveda, user.id_usuario)
        self._audit(user, device, vault_id, "KIT_EMERGENCIA_REVOCADO", "EXITO", ip, user_agent)
        self.db.commit()
        return {"status": "ok", "message": "Emergency Kit revocado."}

    def _audit(self, user, device, vault_id, action, result, ip, user_agent, details=None):
        self.db.add(EventoAuditoria(
            id_usuario=user.id_usuario, id_dispositivo=device.id_dispositivo,
            accion=action, tipo_evento="RECUPERACION_BOVEDA", resultado=result,
            recurso_id=str(vault_id), recurso_tipo="KIT_EMERGENCIA", direccion_ip=ip,
            user_agent=user_agent, detalles=details or {},
        ))
