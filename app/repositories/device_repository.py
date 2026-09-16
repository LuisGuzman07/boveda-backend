from datetime import datetime, timezone
from typing import List, Optional
import uuid
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from app.models.auth import Dispositivo, Sesion
from app.schemas.device import DeviceRegisterRequest


class DeviceRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_user_devices(self, user_id: uuid.UUID) -> List[Dispositivo]:
        """Retorna todos los dispositivos asociados al usuario ordenados por último acceso."""
        stmt = (
            select(Dispositivo)
            .where(
                Dispositivo.id_usuario == user_id,
                Dispositivo.estado != "ELIMINADO",
            )
            .order_by(Dispositivo.ultimo_acceso.desc())
        )
        return list(self.db.scalars(stmt).all())

    def get_device_by_id(self, device_id: uuid.UUID, user_id: uuid.UUID) -> Optional[Dispositivo]:
        """Obtiene un dispositivo por su ID asegurando que pertenezca al usuario especificado."""
        stmt = select(Dispositivo).where(
            Dispositivo.id_dispositivo == device_id,
            Dispositivo.id_usuario == user_id,
        )
        return self.db.scalars(stmt).first()

    def get_device_by_secure_id(self, user_id: uuid.UUID, secure_id: str) -> Optional[Dispositivo]:
        """Busca un dispositivo por su identificador seguro persistente."""
        stmt = select(Dispositivo).where(
            Dispositivo.id_usuario == user_id,
            Dispositivo.identificador_seguro == secure_id,
        )
        return self.db.scalars(stmt).first()

    def create_or_update_device(
        self,
        user_id: uuid.UUID,
        data: DeviceRegisterRequest,
    ) -> Dispositivo:
        """Registra un nuevo dispositivo o actualiza su última conexión y metadatos."""
        now = datetime.now(timezone.utc)
        device = self.get_device_by_secure_id(user_id, data.identificador_seguro)

        if device:
            device.ultimo_acceso = now
            if data.nombre:
                device.nombre = data.nombre
            if data.tipo:
                device.tipo = data.tipo
            if data.sistema_operativo:
                device.sistema_operativo = data.sistema_operativo
            if data.public_key:
                device.public_key = data.public_key
            if data.confiar_dispositivo:
                device.es_confiable = True
            if device.estado == "REVOCADO":
                device.estado = "ACTIVO"
        else:
            device = Dispositivo(
                id_usuario=user_id,
                nombre=data.nombre or "Dispositivo Desconocido",
                tipo=data.tipo or "WEB",
                sistema_operativo=data.sistema_operativo or "Desconocido",
                identificador_seguro=data.identificador_seguro,
                public_key=data.public_key,
                es_confiable=data.confiar_dispositivo,
                estado="ACTIVO",
                fecha_registro=now,
                ultimo_acceso=now,
            )
            self.db.add(device)

        self.db.commit()
        self.db.refresh(device)
        return device

    def set_device_trust(
        self,
        device: Dispositivo,
        es_confiable: bool,
        nombre: Optional[str] = None,
    ) -> Dispositivo:
        """Establece o revoca el estado de confianza del dispositivo."""
        device.es_confiable = es_confiable
        device.ultimo_acceso = datetime.now(timezone.utc)
        if nombre:
            device.nombre = nombre
        self.db.add(device)
        self.db.commit()
        self.db.refresh(device)
        return device

    def revoke_and_delete_device(
        self,
        device: Dispositivo,
        revocado_por: uuid.UUID,
    ) -> None:
        """Revoca las sesiones activas vinculadas a este dispositivo y lo marca como revocado/eliminado."""
        now = datetime.now(timezone.utc)
        # Revocar sesiones asociadas
        stmt_sessions = (
            update(Sesion)
            .where(Sesion.id_dispositivo == device.id_dispositivo, Sesion.revocada == False)
            .values(
                revocada=True,
                motivo_revocacion="DISPOSITIVO_DESVINCULADO",
                ultima_actividad=now,
            )
        )
        self.db.execute(stmt_sessions)

        # Actualizar estado del dispositivo
        device.estado = "REVOCADO"
        device.es_confiable = False
        device.fecha_revocacion = now
        device.revocado_por = revocado_por
        self.db.add(device)
        self.db.commit()
