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

    # --- CU-05: Métodos de Gestión y Revocación Administrativa ---

    def get_device_by_id_global(self, device_id: uuid.UUID) -> Optional[Dispositivo]:
        """Obtiene un dispositivo por su ID sin filtrar por usuario (para uso administrativo)."""
        stmt = select(Dispositivo).where(Dispositivo.id_dispositivo == device_id)
        return self.db.scalars(stmt).first()

    def get_all_devices_admin(
        self,
        query: Optional[str] = None,
        solo_confiables: Optional[bool] = None,
        estado: Optional[str] = None,
    ) -> List[dict]:
        """Retorna todos los dispositivos del sistema con datos del usuario y conteo de sesiones activas."""
        from sqlalchemy import func, or_
        from app.models.auth import Usuario

        # Subquery para contar sesiones activas por dispositivo
        sesiones_subquery = (
            select(
                Sesion.id_dispositivo,
                func.count(Sesion.id_sesion).label("activas_count"),
            )
            .where(Sesion.revocada == False)
            .group_by(Sesion.id_dispositivo)
            .subquery()
        )

        stmt = (
            select(
                Dispositivo,
                Usuario.nombre.label("user_nombre"),
                Usuario.correo.label("user_correo"),
                func.coalesce(sesiones_subquery.c.activas_count, 0).label("sesiones_activas"),
            )
            .join(Usuario, Dispositivo.id_usuario == Usuario.id_usuario)
            .outerjoin(
                sesiones_subquery,
                Dispositivo.id_dispositivo == sesiones_subquery.c.id_dispositivo,
            )
        )

        if solo_confiables is not None:
            stmt = stmt.where(Dispositivo.es_confiable == solo_confiables)

        if estado:
            stmt = stmt.where(Dispositivo.estado == estado)

        if query:
            search_pattern = f"%{query.strip()}%"
            stmt = stmt.where(
                or_(
                    Usuario.nombre.ilike(search_pattern),
                    Usuario.correo.ilike(search_pattern),
                    Dispositivo.nombre.ilike(search_pattern),
                    Dispositivo.sistema_operativo.ilike(search_pattern),
                    Dispositivo.identificador_seguro.ilike(search_pattern),
                )
            )

        stmt = stmt.order_by(Dispositivo.ultimo_acceso.desc())
        results = self.db.execute(stmt).all()

        device_list = []
        for dev, user_nombre, user_correo, sesiones_activas in results:
            device_list.append(
                {
                    "device": dev,
                    "usuario_nombre": user_nombre,
                    "usuario_correo": user_correo,
                    "sesiones_activas": sesiones_activas,
                }
            )
        return device_list

    def revoke_device_by_admin(
        self,
        device: Dispositivo,
        admin_id: uuid.UUID,
        motivo: str = "Revocación administrativa de seguridad",
    ) -> None:
        """CU-05: Invalida el dispositivo y revoca inmediatamente todas las sesiones activas vinculadas."""
        now = datetime.now(timezone.utc)

        # Invalida todas las sesiones activas en la tabla sesion
        stmt_sessions = (
            update(Sesion)
            .where(Sesion.id_dispositivo == device.id_dispositivo, Sesion.revocada == False)
            .values(
                revocada=True,
                motivo_revocacion=f"REVOCADO_POR_ADMINISTRADOR: {motivo}",
                ultima_actividad=now,
            )
        )
        self.db.execute(stmt_sessions)

        # Invalida el dispositivo
        device.estado = "REVOCADO"
        device.es_confiable = False
        device.fecha_revocacion = now
        device.revocado_por = admin_id
        self.db.add(device)
        self.db.commit()

    def revoke_all_devices_for_user(
        self,
        user_id: uuid.UUID,
        admin_id: uuid.UUID,
        motivo: str = "Revocación masiva de terminales por seguridad",
    ) -> int:
        """CU-05: Revoca todos los dispositivos y todas las sesiones de una cuenta."""
        now = datetime.now(timezone.utc)

        # 1. Revocar todas las sesiones del usuario
        stmt_sessions = (
            update(Sesion)
            .where(Sesion.id_usuario == user_id, Sesion.revocada == False)
            .values(
                revocada=True,
                motivo_revocacion=f"REVOCACION_MASIVA_ADMIN: {motivo}",
                ultima_actividad=now,
            )
        )
        self.db.execute(stmt_sessions)

        # 2. Revocar todos los dispositivos del usuario
        stmt_devices = (
            update(Dispositivo)
            .where(Dispositivo.id_usuario == user_id, Dispositivo.estado != "REVOCADO")
            .values(
                estado="REVOCADO",
                es_confiable=False,
                fecha_revocacion=now,
                revocado_por=admin_id,
            )
        )
        result = self.db.execute(stmt_devices)
        self.db.commit()
        return result.rowcount or 0
